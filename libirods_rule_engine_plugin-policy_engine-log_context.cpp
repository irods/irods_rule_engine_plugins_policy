
#include "policy_engine.hpp"
#include "policy_engine_parameter_capture.hpp"
#include "exec_as_user.hpp"
#include "filesystem.hpp"
#include "policy_engine_configuration_manager.hpp"

#include "rsModAVUMetadata.hpp"
#include "rsOpenCollection.hpp"
#include "rsReadCollection.hpp"
#include "rsCloseCollection.hpp"

namespace {

    namespace pe = irods::policy_engine;

    using json = nlohmann::json;

    irods::error log_context(const pe::context& ctx)
    {
        std::cout << "PARAMETERS:    [" << ctx.parameters.dump(4)    << "]\n";
        std::cout << "CONFIGURATION: [" << ctx.configuration.dump(4) << "]\n";

        return SUCCESS();

    } // log_context

} // namespace

const char usage[] = R"(
{
    "id": "file:///var/lib/irods/configuration_schemas/v3/policy_engine_usage.json",
    "$schema": "http://json-schema.org/draft-04/schema#",
    "description": "This is a test, this is only a test."
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
               , "irods_policy_log_context"
               , usage
               , log_context);
} // plugin_factory
