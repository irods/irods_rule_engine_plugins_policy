
#include "policy_engine.hpp"
#include "exec_as_user.hpp"
#include "filesystem.hpp"
#include "policy_engine_configuration_manager.hpp"

#include "rsModAVUMetadata.hpp"
#include "rsOpenCollection.hpp"
#include "rsReadCollection.hpp"
#include "rsCloseCollection.hpp"

namespace {

    namespace pe = irods::policy_engine;

    irods::error testing_policy(const pe::context& ctx)
    {
        std::string user_name{}, object_path{}, source_resource{}, destination_resource{};

        if(ctx.parameters.is_array()) {
            using fsp = irods::experimental::filesystem::path;

            std::string tmp_coll_name{}, tmp_data_name{};

            std::tie(user_name, tmp_coll_name, tmp_data_name) =
                irods::extract_array_parameters<3, std::string>(ctx.parameters);

            object_path = (fsp{tmp_coll_name} / fsp{tmp_data_name}).string();

        }
        else {
            std::tie(user_name, object_path, source_resource, destination_resource) =
                irods::extract_dataobj_inp_parameters(
                      ctx.parameters
                    , irods::tag_first_resc);
        }

        auto comm  = ctx.rei->rsComm;
        std::string event = ctx.parameters["event"];

        modAVUMetadataInp_t set_op{
              "add"
            , "-d"
            , const_cast<char*>(object_path.c_str())
            , "irods_policy_testing_policy"
            , const_cast<char*>(event.c_str())
            , ""};

        auto status = rsModAVUMetadata(comm, &set_op);
        if(status < 0) {
            return ERROR(
                       status,
                       boost::format("Failed to invoke test_policy for [%s] with metadata [%s] [%s]")
                       % object_path
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
