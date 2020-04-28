
#include "policy_engine.hpp"
#include "policy_engine_parameter_capture.hpp"
#include "exec_as_user.hpp"
#include "policy_engine_configuration_manager.hpp"
#include "data_verification_utilities.hpp"

namespace pe = irods::policy_engine;

namespace {
    irods::error data_verification_policy(const pe::context& ctx)
    {
        pe::configuration_manager cfg_mgr{ctx.instance_name, ctx.configuration};

        std::string user_name{}, logical_path{}, source_resource{}, destination_resource{}, verification_type{}, unit{};

        // may be within the configuration
        irods::error err{};
        std::tie(err, source_resource) = cfg_mgr.get_value("source_resource", "");

        // query processor invocation
        if(ctx.parameters.contains("query_results")) {
            using fsp = irods::experimental::filesystem::path;

            std::string tmp_coll_name{}, tmp_data_name{};

            std::tie(user_name, tmp_coll_name, tmp_data_name, destination_resource) =
                extract_array_parameters<4, std::string>(ctx.parameters.at("query_results"));

            logical_path = (fsp{tmp_coll_name} / fsp{tmp_data_name}).string();
        }
        else {
            // event handler or direct call invocation
            std::tie(user_name, logical_path, source_resource, destination_resource) =
                extract_dataobj_inp_parameters(ctx.parameters, tag_first_resc);
        }

        if(source_resource.empty()) {
            return ERROR(
                       SYS_INVALID_INPUT_PARAM,
                       "irods_policy_data_verification :: source_resource is not specified");
        }

        std::string attribute{};
        std::tie(err, attribute) = cfg_mgr.get_value("attribute", "irods::verification::type");

        auto comm = ctx.rei->rsComm;

        std::tie(verification_type, unit) = get_metadata_for_resource(comm, attribute, destination_resource);

        auto verif_fcn = [&](auto& comm) {
            return irods::verify_replica_for_destination_resource(
                         &comm
                       , verification_type
                       , logical_path
                       , source_resource
                       , destination_resource);};

        auto verified = irods::exec_as_user(*comm, user_name, verif_fcn);

        if(verified) {
            return SUCCESS();
        }
        else {
            return ERROR(
                    UNMATCHED_KEY_OR_INDEX,
                    boost::format("verification [%s] failed from [%s] to [%s]")
                        % verification_type
                        % source_resource
                        % destination_resource);
        }

    } // data_verification_policy

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
               , "irods_policy_data_verification"
               , usage
               , data_verification_policy);

} // plugin_factory
