
#include "policy_engine.hpp"
#include "policy_engine_parameter_capture.hpp"

#include "irods_hierarchy_parser.hpp"
#include "irods_server_api_call.hpp"
#include "exec_as_user.hpp"

#include "physPath.hpp"
#include "apiNumber.h"

namespace {
    int replicate_object_to_resource(
          rsComm_t*          _comm
        , const std::string& _user_name
        , const std::string& _logical_path
        , const std::string& _source_resource
        , const std::string& _destination_resource)
    {
        dataObjInp_t data_obj_inp{};
        rstrcpy(data_obj_inp.objPath, _logical_path.c_str(), MAX_NAME_LEN);
        data_obj_inp.createMode = getDefFileMode();
        addKeyVal(&data_obj_inp.condInput, RESC_NAME_KW,      _source_resource.c_str());
        addKeyVal(&data_obj_inp.condInput, DEST_RESC_NAME_KW, _destination_resource.c_str());

        if(_comm->clientUser.authInfo.authFlag >= LOCAL_PRIV_USER_AUTH) {
            addKeyVal(&data_obj_inp.condInput, ADMIN_KW, "true" );
        }

        transferStat_t* trans_stat{};

        auto repl_fcn = [&](auto& comm){
            auto ret = irods::server_api_call(DATA_OBJ_REPL_AN, _comm, &data_obj_inp, &trans_stat);
            free(trans_stat);
            return ret;};

        return irods::exec_as_user(*_comm, _user_name, repl_fcn);

    } // replicate_object_to_resource

    namespace pe = irods::policy_engine;

    irods::error replication_policy(const pe::context ctx)
    {
        std::string user_name{}, logical_path{}, source_resource{}, destination_resource{};

        std::tie(user_name, logical_path, source_resource, destination_resource) =
            capture_parameters(ctx.parameters, tag_first_resc);

        auto comm = ctx.rei->rsComm;

        if(!destination_resource.empty()) {
            // direct call invocation
            int err = replicate_object_to_resource(
                            comm
                          , user_name
                          , logical_path
                          , source_resource
                          , destination_resource);
            if(err < 0) {
                return ERROR(
                          err,
                          boost::format("failed to replicate [%s] from [%s] to [%s]")
                          % logical_path
                          % source_resource
                          % destination_resource);
            }
        }
        else {
            // event handler invocation
            if(ctx.configuration.empty()) {
                THROW(
                    SYS_INVALID_INPUT_PARAM,
                    boost::format("%s - destination_resource is empty and configuration is not provided")
                    % ctx.policy_name);
            }

            destination_resource = extract_object_parameter<std::string>("destination_resource", ctx.configuration);
            if(!destination_resource.empty()) {
                int err = replicate_object_to_resource(
                                comm
                              , user_name
                              , logical_path
                              , source_resource
                              , destination_resource);
                if(err < 0) {
                    return ERROR(
                              err,
                              boost::format("failed to replicate [%s] from [%s] to [%s]")
                              % logical_path
                              % source_resource
                              % destination_resource);
                }
            }
            else {
                if(ctx.configuration.find("source_to_destination_map") ==
                   ctx.configuration.end()) {
                    THROW(
                        SYS_INVALID_INPUT_PARAM,
                        boost::format("%s - destination_resource or source_to_destination_map not provided")
                        % ctx.policy_name);
                }

                auto src_dst_map{ctx.configuration.at("source_to_destination_map")};

                auto dst_resc_arr{src_dst_map.at(source_resource)};
                auto destination_resources = dst_resc_arr.get<std::vector<std::string>>();
                irods::error ret{SUCCESS()};
                for( auto& dest : destination_resources) {
                    int err = replicate_object_to_resource(
                                    comm
                                  , user_name
                                  , logical_path
                                  , source_resource
                                  , dest);
                    if(err < 0) {
                        ret = PASSMSG(
                                  boost::str(boost::format("failed to replicate [%s] from [%s] to [%s]")
                                  % logical_path
                                  % source_resource),
                                  ret);
                    }
                }

                if(!ret.ok()) {
                    return ret;
                }
            }
        }

        return SUCCESS();

    } // replication_policy

} // namespace

const char usage[] = R"(
{
    "id": "file:///var/lib/irods/configuration_schemas/v3/policy_engine_usage.json",
    "$schema": "http://json-schema.org/draft-04/schema#",
    "description": ""
        "input_interfaces": [
            {
                "name" : "event_handler-collection_modified",
                "description" : "",
                "json_schema" : ""
            },
            {
                "name" :  "event_handler-data_object_modified",
                "description" : "",
                "json_schema" : ""
            },
            {
                "name" :  "event_handler-metadata_modified",
                "description" : "",
                "json_schema" : ""
            },
            {
                "name" :  "event_handler-user_modified",
                "description" : "",
                "json_schema" : ""
            },
            {
                "name" :  "event_handler-resource_modified",
                "description" : "",
                "json_schema" : ""
            },
            {
                "name" :  "direct_invocation",
                "description" : "",
                "json_schema" : ""
            },
            {
                "name" :  "query_results"
                "description" : "",
                "json_schema" : ""
            },
        ],
    "output_json_for_validation" : ""
}
)";


extern "C"
pe::plugin_pointer_type plugin_factory(
      const std::string& _plugin_name
    , const std::string&)
{
    return pe::make(
             _plugin_name
            , "irods_policy_data_replication"
            , usage
            , replication_policy);
} // plugin_factory
