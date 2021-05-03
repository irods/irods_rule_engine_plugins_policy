
#include "policy_composition_framework_policy_engine.hpp"
#include "policy_composition_framework_parameter_capture.hpp"
#include "policy_composition_framework_configuration_manager.hpp"

#include "data_verification_utilities.hpp"
#include "irods_resource_backport.hpp"

#include "rsFileChksum.hpp"

namespace {

    // clang-format off
    namespace pc   = irods::policy_composition;
    namespace pe   = irods::policy_composition::policy_engine;
    namespace fs   = irods::experimental::filesystem;
    namespace fsvr = irods::experimental::filesystem::server;
    using     json = nlohmann::json;
    // clang-format on

    irods::error verify_checksum(const pe::context& ctx, pe::arg_type out)
    {
        auto comm = ctx.rei->rsComm;

        std::string user_name{}, logical_path{}, source_resource{}, destination_resource{};

        std::tie(user_name, logical_path, source_resource, destination_resource) =
            capture_parameters(ctx.parameters, tag_last_resc);

        auto catalog_checksum = std::string{};
        auto resc_hier = std::string{};
        auto phys_path = std::string{};
        auto data_size = std::string{};
        auto coll_name = std::string{};
        auto data_name = std::string{};

        irods::get_object_and_collection_from_path(
            logical_path,
            coll_name,
            data_name);

        const auto query_str = fmt::format(
                               "SELECT DATA_CHECKSUM, DATA_RESC_HIER, DATA_PATH, DATA_SIZE WHERE DATA_NAME = '{}'"
                               " AND COLL_NAME = '{}' AND RESC_NAME = '{}'"
                               , data_name
                               , coll_name
                               , source_resource);

        irods::query<rsComm_t> qobj{comm, query_str};
        if(qobj.size() > 0) {
            catalog_checksum = qobj.front()[0];
            resc_hier        = qobj.front()[1];
            phys_path        = qobj.front()[2];
            data_size        = qobj.front()[3];
        }

        std::string location;
        if (const auto err = irods::get_loc_for_hier_string(resc_hier.c_str(), location); !err.ok()) {
            return ERROR(err.code(), fmt::format("{} :: get_loc_for_hier_string failed for {} on {} msg [{}]"
                         , "irods_policy_verify_checksum"
                         , logical_path
                         , source_resource
                         , err.result()));
        }

        fileChksumInp_t inp{};
        inp.dataSize = std::atoi(data_size.c_str());
        rstrcpy(inp.addr.hostAddr, location.c_str(),      NAME_LEN);
        rstrcpy(inp.fileName,      phys_path.c_str(),     MAX_NAME_LEN);
        rstrcpy(inp.rescHier,      resc_hier.c_str(),     MAX_NAME_LEN);
        rstrcpy(inp.objPath,       logical_path.c_str(),  MAX_NAME_LEN);

        char* computed_checksum{};
        if(const auto ec = rsFileChksum(comm, &inp, &computed_checksum); ec < 0) {
            return ERROR(ec, fmt::format("{} :: rsFileChksum failed for {} on {}"
                         , "irods_policy_verify_checksum"
                         , logical_path
                         , source_resource));
        }

        if(!catalog_checksum.empty() && catalog_checksum != computed_checksum) {
            const auto msg = fmt::format("checksum mismatch for [{}] on resource [{}] computed [{}] catalog [{}]"
                                        , logical_path
                                        , source_resource
                                        , computed_checksum
                                        , catalog_checksum);

            const auto le = pe::get_log_errors_flag(ctx.parameters, ctx.configuration);
            if(le) {
                rodsLog(LOG_ERROR, msg.c_str());
            }

            return ERROR(USER_CHKSUM_MISMATCH, msg);
        }

        return SUCCESS();

    } // verify_checksum

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
               , "irods_policy_verify_checksum"
               , usage
               , verify_checksum);
} // plugin_factory
