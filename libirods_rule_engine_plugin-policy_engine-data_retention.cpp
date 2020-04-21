
#include <algorithm>
#include <iostream>

#include "policy_engine.hpp"
#include "exec_as_user.hpp"
#include "irods_server_api_call.hpp"
#include "apiNumber.h"
#include "policy_engine_configuration_manager.hpp"

#include "json.hpp"

namespace pe = irods::policy_engine;

namespace {

    namespace mode {
        static const std::string remove_all{"remove_all_replicas"};
        static const std::string trim_single{"trim_single_replica"};
    };

    int remove_data_object(
          int                _api_index
        , rsComm_t*          _comm
        , const std::string& _user_name
        , const std::string& _logical_path
        , const std::string& _source_resource = {})
    {
        dataObjInp_t obj_inp{};
        rstrcpy(
              obj_inp.objPath
            , _logical_path.c_str()
            , sizeof(obj_inp.objPath));

        addKeyVal(
              &obj_inp.condInput
            , COPIES_KW
            , "1");

        if(_comm->clientUser.authInfo.authFlag >= LOCAL_PRIV_USER_AUTH) {
            addKeyVal(
                  &obj_inp.condInput
                , ADMIN_KW
                , "true" );
        }

        if(!_source_resource.empty()) {
            addKeyVal(
                  &obj_inp.condInput
                , RESC_NAME_KW
                , _source_resource.c_str());
        }

        auto trim_fcn = [&](auto& comm) {
            return irods::server_api_call(_api_index, &comm, &obj_inp);
        };

        return irods::exec_as_user(*_comm, _user_name, trim_fcn);

    } // remove_data_object



    // assumes _resources are sorted
    std::tuple<bool, std::vector<std::string>>
    participating_resources_without_preservation(
          rsComm_t*          _comm
        , const std::string& _attribute
        , const std::string& _logical_path
        , const std::string& _resource) {
        using fsp = irods::experimental::filesystem::path;

        fsp path{_logical_path};
        const auto coll_name = path.parent_path();
        const auto data_name = path.object_name();

        std::vector<std::string> all_resources{};
        if(_resource.empty()) {
            // query for list of all participating resources
            auto qstr{boost::str(boost::format(
                      "SELECT RESC_NAME WHERE COLL_NAME = '%s' AND DATA_NAME = '%s'")
                      % coll_name.string()
                      % data_name.string())};

            irods::query qobj{_comm, qstr};

            // may get no results, early exit
            if(qobj.size() <= 0) {
                return std::make_tuple(false, all_resources);
            }

            for(auto r : qobj) {
                all_resources.push_back(r[0]);
            }
        }
        else {
            all_resources.push_back(_resource);
        }

        // query for list of participating resources which have the attribute
        auto qstr = boost::str(boost::format(
                    "SELECT RESC_NAME WHERE COLL_NAME = '%s' AND DATA_NAME = '%s' AND META_RESC_ATTR_NAME = '%s' AND RESC_NAME IN (")
                    % coll_name.string()
                    % data_name.string()
                    % _attribute);
        for(auto& r : all_resources) {
            qstr += "'" + r + "', ";
        }
        qstr += ")";

        std::vector<std::string> md_resources{};

        irods::query md_qobj{_comm, qstr};

        // may get no results, early exit
        if(md_qobj.size() <= 0) {
            return std::make_tuple(_resource.empty(), all_resources);
        }

        for(auto r : md_qobj) {
            md_resources.push_back(r[0]);
        }

        std::vector<std::string> final_resources{};

        std::set_difference(
              all_resources.begin()
            , all_resources.end()
            , md_resources.begin()
            , md_resources.end()
            , std::inserter(
                final_resources
              , final_resources.begin()));

        return std::make_tuple(false, final_resources);

    } // participating_resources_without_preservation



    irods::error data_retention_policy(const pe::context& ctx)
    {
        pe::configuration_manager cfg_mgr{ctx.instance_name, ctx.configuration};

        std::string mode{}, user_name{}, logical_path{}, source_resource{}, destination_resource{}, attribute{};

        // query processor invocation
        if(ctx.parameters.contains("query_results")) {
            using fsp = irods::experimental::filesystem::path;
            std::string tmp_coll_name{}, tmp_data_name{};

            auto results = ctx.parameters.at("query_results");
            user_name     = results.at(0);
            tmp_coll_name = results.at(1);
            tmp_data_name = results.at(2);
            if(results.size() > 3) {
                source_resource = results.at(3);
            }

            logical_path = (fsp{tmp_coll_name} / fsp{tmp_data_name}).string();
        }
        else {
            // event handler or direct call invocation
            std::tie(user_name, logical_path, source_resource, destination_resource) =
                irods::extract_dataobj_inp_parameters(
                      ctx.parameters
                    , irods::tag_first_resc);
        }

        auto err = SUCCESS();
        std::vector<std::string> resource_white_list{};
        std::tie(err, resource_white_list) = cfg_mgr.get_value(
                                                    "resource_white_list"
                                                  , resource_white_list);
        if(err.ok()) {
            if(source_resource.empty()) {
                return ERROR(
                           SYS_INVALID_INPUT_PARAM
                         , "resource whitelist provided with empty source resource");
            }

            // white list provided, the source resource is matched
            if(std::find(std::begin(resource_white_list)
                       , std::end(resource_white_list)
                       , source_resource) ==
               std::end(resource_white_list)) {
                return ERROR(
                           SYS_INVALID_INPUT_PARAM,
                           boost::format("source resource not matched [%s]")
                           % source_resource);
            }
        }

        std::tie(err, attribute) = cfg_mgr.get_value(
                                         "attribute"
                                       , "irods::retention::preserve_replicas");

        auto comm = ctx.rei->rsComm;

        auto [remove_all_replicas, resources_to_remove] =
        participating_resources_without_preservation(
              comm
            , attribute
            , logical_path
            , source_resource);

        // remove all replicas - requires a call to unlink, not trim
        if(remove_all_replicas) {
            const auto ret = remove_data_object(
                                   DATA_OBJ_UNLINK_AN
                                 , comm
                                 , user_name
                                 , logical_path);
            if(ret < 0) {
                 return ERROR(
                           ret,
                           boost::format("failed to remove [%s] from [%s]")
                           % logical_path
                           % source_resource);
            }

        }
        // trim a specific list of replicas
        else {
            for(const auto& src : resources_to_remove) {
                const auto ret = remove_data_object(
                                       DATA_OBJ_TRIM_AN
                                     , comm
                                     , user_name
                                     , logical_path
                                     , src);
                if(ret < 0) {
                     return ERROR(
                               ret,
                               boost::format("failed to remove [%s] from [%s]")
                               % logical_path
                               % source_resource);
                }
            } // for src
        }

        return SUCCESS();

    } // data_retention_policy

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
    , const std::string&) {

    return pe::make(
                 _plugin_name
               , "irods_policy_data_retention"
               , usage
               , data_retention_policy);

} // plugin_factory
