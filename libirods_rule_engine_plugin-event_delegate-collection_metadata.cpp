
#include "policy_engine.hpp"
#include "policy_engine_parameter_capture.hpp"
#include "policy_engine_configuration_manager.hpp"
#include "json.hpp"

namespace {
    namespace pe   = irods::policy_engine;
    namespace fs   = irods::experimental::filesystem;
    namespace fsvr = irods::experimental::filesystem::server;

    using fsp  = fs::path;
    using json = nlohmann::json;

    irods::error event_delegate_collection_metadata(const pe::context& ctx)
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

        const fsp root_path("/");
        for(auto& policy : policies_to_invoke) {
            json conditional{};

            if(policy.contains("conditional") && policy.at("conditional").contains("metadata")) {
                conditional = policy.at("conditional").at("metadata");
            }
            else {
                rodsLog(
                    LOG_ERROR,
                    "event_delegate-collection_metadata does not contain conditional metadata objects");
                continue;
            }

            fsp current_path{logical_path};
            std::string entity_type{"collection"};
            try {
                std::string entity_type = (fsvr::is_data_object(*comm, current_path)) ?
                                                "data_object" : "collection";
            }
            catch(...) {
            }

            while(current_path != root_path) {
                if(fsvr::is_data_object(*comm, current_path)) {
                    current_path = current_path.parent_path();
                    continue;
                }

                std::vector<fs::metadata> fsmd{};
                try {
                    fsmd = fsvr::get_metadata(*comm, current_path);
                    if(fsmd.empty()) {
                        current_path = current_path.parent_path();
                        continue;
                    }
                }
                catch(...) {
                    current_path = current_path.parent_path();
                    continue;
                }

                bool found_a_match{false};
                fs::metadata matched_md{};
                for(auto&& md : fsmd) {
                    json obj = { {"attribute", md.attribute}
                               , {"value",     md.value}
                               , {"units",     md.units}};
                    if(irods::evaluate_metadata_conditional(conditional, obj)) {
                        found_a_match = true;
                        matched_md = md;
                        break;
                    }
                }

                if(!found_a_match) {
                    current_path = current_path.parent_path();
                    continue;
                }

                auto cfg{policy["configuration"]};
                std::string pn{policy["policy"]};

                std::string operation{};
                if(ctx.parameters.contains("operation")) {
                    operation = ctx.parameters.at("operation");
                }

                auto new_params = ctx.parameters;
                new_params["conditional"]["metadata"] = {
                    {"operation",   operation},
                    {"entity_type", entity_type},
                    {"attribute",   matched_md.attribute},
                    {"value",       matched_md.value},
                    {"units",       matched_md.units}
                };

                std::string params{new_params.dump()};
                std::string config{cfg.dump()};

                std::list<boost::any> args;
                args.push_back(boost::any(std::ref(params)));
                args.push_back(boost::any(std::ref(config)));
                irods::invoke_policy(ctx.rei, pn, args);

                current_path = current_path.parent_path();

            } // while current_path

        } // for policies_to_invoke

        return SUCCESS();

    } // event_delegate_collection_metadata
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
               , "irods_policy_event_delegate_collection_metadata"
               , usage
               , event_delegate_collection_metadata);
} // plugin_factory
