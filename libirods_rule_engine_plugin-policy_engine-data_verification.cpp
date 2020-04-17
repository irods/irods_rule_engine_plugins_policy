
#include "policy_engine.hpp"
#include "exec_as_user.hpp"
#include "policy_engine_configuration_manager.hpp"
#include "data_verification_utilities.hpp"

namespace pe = irods::policy_engine;

namespace {
    irods::error data_verification_policy(const pe::context& ctx)
    {
        pe::configuration_manager cfg_mgr{ctx.instance_name, ctx.configuration};

        std::string user_name{}, object_path{}, source_resource{}, destination_resource{}, verification_type{}, unit{};

        std::tie(user_name, object_path, source_resource, destination_resource) =
            irods::capture_parameters(
                  ctx.parameters
                , irods::tag_last_resc);

        auto [err, attribute] = cfg_mgr.get_value("attribute", "irods::verification::type");

        auto comm = ctx.rei->rsComm;

        std::tie(verification_type, unit) = irods::get_metadata_for_resource(comm, attribute, destination_resource);

        auto verif_fcn = [&](auto& comm) {
            return irods::verify_replica_for_destination_resource(
                         &comm
                       , verification_type
                       , object_path
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
