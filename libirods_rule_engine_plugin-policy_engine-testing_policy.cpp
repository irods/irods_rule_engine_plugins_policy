
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

    auto entity_type_to_option(const std::string& _type) {
        if("data_object" == _type) {
            return "-d";
        }
        else if("collection" == _type) {
            return "-C";
        }
        else if("user" == _type) {
            return "-u";
        }
        else if("resource" == _type) {
            return "-R";
        }
        else {
            return "unsupported";
        }
    } // entity_type_to_option

    auto entity_type_to_target(const std::string& _type, json _params) {
        if("data_object" == _type) {
            return _params.at("logical_path").get<std::string>();
        }
        else if("collection" == _type) {
            return _params.at("logical_path").get<std::string>();
        }
        else if("user" == _type) {
            return _params.at("user_name").get<std::string>();
        }
        else if("resource" == _type) {
            return _params.at("source_resource").get<std::string>();
        }
        else {
            return std::string{"unsupported"};
        }
    } // entity_type_to_option

    namespace fs   = irods::experimental::filesystem;
    namespace fsvr = irods::experimental::filesystem::server;

    irods::error testing_policy(const pe::context& ctx)
    {
        std::string user_name{}, logical_path{}, source_resource{}, destination_resource{};

        std::tie(user_name, logical_path, source_resource, destination_resource) =
            capture_parameters(ctx.parameters, tag_first_resc);

        auto comm  = ctx.rei->rsComm;
        std::string event = ctx.parameters["event"];

        std::string entity_type, option, target;
        modAVUMetadataInp_t set_op{};
        if("METADATA" == event) {
            if(ctx.parameters.contains("conditional")) {
                if(ctx.parameters.contains("metadata")) {
                    if(ctx.parameters.at("conditional").at("metadata").contains("entity_type")) {
                        entity_type = ctx.parameters.at("conditional").at("metadata").at("entity_type");
                    }
                }
            }
            else if(ctx.parameters.contains("metadata")) {
                if(ctx.parameters.at("metadata").contains("entity_type")) {
                    entity_type = ctx.parameters.at("metadata").at("entity_type");
                }
            }
            else {
                return ERROR(
                        SYS_INVALID_INPUT_PARAM,
                        "testing_policy :: missing 'entity_type' in 'metadata'");
            }

            option = entity_type_to_option(entity_type);
            target = entity_type_to_target(entity_type, ctx.parameters);
            set_op.arg0 = "add";
            set_op.arg1 = const_cast<char*>(option.c_str());
            set_op.arg2 = const_cast<char*>(target.c_str());
            set_op.arg3 = "irods_policy_testing_policy";
            set_op.arg4 = const_cast<char*>(event.c_str());
        }
        else {
            if(!fsvr::exists(*comm, logical_path)) {
                logical_path = fs::path(logical_path).parent_path();
            }

            std::string op = fsvr::is_data_object(*comm, logical_path) ? "-d" : "-C";

            set_op.arg0 = "add";
            set_op.arg1 = const_cast<char*>(op.c_str());
            set_op.arg2 = const_cast<char*>(logical_path.c_str());
            set_op.arg3 = "irods_policy_testing_policy";
            set_op.arg4 = const_cast<char*>(event.c_str());
        }

        auto status = rsModAVUMetadata(comm, &set_op);
        if(status < 0) {
            return ERROR(
                       status,
                       boost::format("Failed to invoke test_policy for [%s] with metadata [%s] [%s]")
                       % logical_path
                       % "irods_testing_policy"
                       % event);
        }

        return SUCCESS();

    } // testing_policy

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
               , "irods_policy_testing_policy"
               , usage
               , testing_policy);
} // plugin_factory
