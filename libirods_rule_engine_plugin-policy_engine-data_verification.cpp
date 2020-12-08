
#include "policy_composition_framework_policy_engine.hpp"
#include "policy_composition_framework_parameter_capture.hpp"
#include "exec_as_user.hpp"
#include "policy_composition_framework_configuration_manager.hpp"
#include "data_verification_utilities.hpp"

namespace pe = irods::policy_engine;

namespace {
    namespace verification {
        static const std::string catalog("catalog");
        static const std::string filesystem("filesystem");
        static const std::string checksum("checksum");
    }

    irods::error data_verification_policy(const pe::context& ctx)
    {
        auto log_actions = pe::get_log_errors_flag(ctx.parameters, ctx.configuration);

        if(log_actions) {
            std::cout << "irods_policy_data_verification :: parameters " << ctx.parameters.dump(4) << "\n";
        }

        pe::configuration_manager cfg_mgr{ctx.instance_name, ctx.configuration};

        std::string user_name{}, logical_path{}, source_resource{}, destination_resource{}, type{}, units{};

        std::tie(user_name, logical_path, source_resource, destination_resource) =
            capture_parameters(ctx.parameters, tag_first_resc);

        // may be statically configured
        source_resource = cfg_mgr.get("source_resource", source_resource);

        if(source_resource.empty()) {
            return ERROR(
                       SYS_INVALID_INPUT_PARAM,
                       "irods_policy_data_verification :: source_resource is not specified");
        }

        auto attribute = cfg_mgr.get("attribute", "irods::verification::type");

        auto comm = ctx.rei->rsComm;

        std::tie(type, units) = get_metadata_for_resource(comm, attribute, destination_resource);

        if(type.empty()) {
            type = verification::catalog;
        }

        if(log_actions) {
            std::cout << "irods_policy_data_verification :: verifying " << logical_path
                      << " with type " << type << " on resource " << destination_resource << "\n";
        }

        auto verif_fcn = [&](auto& comm) {
            return irods::verify_replica_for_destination_resource(
                         &comm
                       , type
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
                        % type
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
