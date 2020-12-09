
#include "policy_engine.hpp"
#include "policy_engine_parameter_capture.hpp"
#include "policy_engine_configuration_manager.hpp"
#include "json.hpp"

namespace {
    namespace pe   = irods::policy_composition::policy_engine;
    namespace fs   = irods::experimental::filesystem;
    namespace fsvr = irods::experimental::filesystem::server;

    using fsp  = fs::path;
    using json = nlohmann::json;

    irods::error event_generator_object_metadata(const pe::context& ctx)
    {
        auto comm{ctx.rei->rsComm};

        pe::configuration_manager cfg_mgr{ctx.instance_name, ctx.configuration};

        auto policies_to_invoke = cfg_mgr.get("policies_to_invoke", json::array());
        if(policies_to_invoke.empty()) {
            return ERROR(
                       SYS_INVALID_INPUT_PARAM,
                       "policies_to_invoke is empty for event delegate");
        }

        std::string user_name{}, logical_path{}, source_resource{}, destination_resource{};
        std::tie(user_name, logical_path, source_resource, destination_resource) =
                capture_parameters(ctx.parameters, tag_first_resc);

        for(auto& policy : policies_to_invoke) {
            std::string policy_name{policy["policy"]};
            std::string config{policy["configuration"].dump()};

            fsp path{logical_path};

            if(fsvr::is_collection(*comm, path)) {
                rodsLog(
                    LOG_ERROR,
                    "even_generator-object_metadata :: [%s] is a collection",
                    logical_path.c_str());
                continue;
            }

            std::vector<fs::metadata> object_metadata{};
            try {
                object_metadata = fsvr::get_metadata(*comm, path);
                if(object_metadata.empty()) {
                    continue;
                }
            }
            catch(...) {
                continue;
            }

            std::string operation{};
            if(ctx.parameters.contains("operation")) {
                operation = ctx.parameters.at("operation");
            }

            for(auto && md : object_metadata) {
                auto new_params = ctx.parameters;
                new_params["event_type"] = "METADATA";
                new_params["metadata"] = {
                    {"operation",   operation},
                    {"entity_type", "data_object"},
                    {"attribute",   md.attribute},
                    {"value",       md.value},
                    {"units",       md.units}
                };

                new_params["logical_path"] = path.c_str();
                std::string params{new_params.dump()};

                std::list<boost::any> args;
                args.push_back(boost::any(std::ref(params)));
                args.push_back(boost::any(std::ref(config)));

                try {
                    irods::invoke_policy(ctx.rei, policy_name, args);
                }
                catch(...) {
                    rodsLog(
                        LOG_ERROR,
                        "caught exception in object metadata generator\n");
                }

            } // for md

        } // for policies_to_invoke

        return SUCCESS();

    } // event_generator_object_metadata
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
               , "irods_policy_event_generator_object_metadata"
               , usage
               , event_generator_object_metadata);
} // plugin_factory
