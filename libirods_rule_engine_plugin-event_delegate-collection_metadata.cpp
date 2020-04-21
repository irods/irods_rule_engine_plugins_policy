
#include "policy_engine.hpp"
#include "event_handler_utilities.hpp"
#include "policy_engine_configuration_manager.hpp"
#include "json.hpp"

namespace {
    namespace pe   = irods::policy_engine;
    namespace fs   = irods::experimental::filesystem;
    namespace fsvr = irods::experimental::filesystem::server;

    using fsp  = fs::path;
    using json = nlohmann::json;

    auto metadata_is_equivalent(
          const json&                      metadata_to_compare
        , const std::vector<fs::metadata>& filesystem_metadata) -> std::tuple<bool, fs::metadata>
    {
        std::string attribute, value, units;

        if(metadata_to_compare.find("attribute") != metadata_to_compare.end()) {
            attribute = metadata_to_compare["attribute"];
        }

        if(metadata_to_compare.find("value") != metadata_to_compare.end()) {
            value = metadata_to_compare["value"];
        }

        if(metadata_to_compare.find("units") != metadata_to_compare.end()) {
            units = metadata_to_compare["units"];
        }

        const fs::metadata mmd{
              attribute
            , value
            , units
        };

        if(mmd.attribute.empty() && mmd.value.empty() && mmd.units.empty()) {
            return std::make_tuple(false, fs::metadata{});
        }

        fs::comparison_fields fields {
              mmd.attribute.size() > 0
            , mmd.value.size()     > 0
            , mmd.units.size()     > 0
        };

        for(const auto& fsmd : filesystem_metadata) {
            if(fs::compare_metadata(mmd, fsmd, fields)) {
                return std::make_tuple(true, fsmd);
            }
        }

        return std::make_tuple(false, fs::metadata{});

    } // metadata_is_equivalent

    irods::error event_delegate_collection_metadata(const pe::context& ctx)
    {
        auto comm{ctx.rei->rsComm};

        pe::configuration_manager cfg_mgr{ctx.instance_name, ctx.configuration};

        irods::error err{};
        auto policies_to_invoke{json::array()};
        std::tie(err, policies_to_invoke) = cfg_mgr.get_value(
                                                  "policies_to_invoke"
                                                , policies_to_invoke);
        if(policies_to_invoke.empty()) {
            return ERROR(
                       SYS_INVALID_INPUT_PARAM,
                       "policies_to_invoke is empty for event delegate");
        }


        std::string user_name{}, logical_path{}, source_resource{}, destination_resource{};
        std::tie(user_name, logical_path, source_resource, destination_resource) =
            irods::capture_parameters(
                  ctx.parameters
                , irods::tag_first_resc);

        const fsp root_path("/");
        for(auto& policy : policies_to_invoke) {
            json policy_metadata{};

            if(policy.contains("conditional") && policy.at("conditional").contains("metadata")) {
                policy_metadata = policy.at("conditional").at("metadata");
            }
            else {
                rodsLog(
                    LOG_ERROR,
                    "event_delegate-collection_metadata does not contain conditional metadata objects");
                continue;
            }

            if(policy_metadata.contains("entity_type") &&
               ctx.parameters.contains("metadata") &&
               ctx.parameters.at("metadata").contains("entity_type")) {
               if(policy_metadata.at("entity_type") !=
                  ctx.parameters.at("metadata").at("entity_type")) {
                   continue;
               }
            }

            fsp current_path{logical_path};
            const std::string entity_type = (fsvr::is_data_object(*comm, current_path)) ?
                                            "data_object" : "collection";

            while(current_path != root_path) {
                if(fsvr::is_data_object(*comm, current_path)) {
                    current_path = current_path.parent_path();
                    continue;
                }

                auto md{fsvr::get_metadata(*comm, current_path)};
                if(md.empty()) {
                    current_path = current_path.parent_path();
                    continue;
                }

                bool ec{false}; fs::metadata fsmd{};
                if(std::tie(ec, fsmd) = metadata_is_equivalent(policy_metadata, md); !ec) {
                    current_path = current_path.parent_path();
                    continue;
                }

                auto cfg{policy["configuration"]};
                std::string pn{policy["policy"]};

                auto new_params = ctx.parameters;
                new_params["conditional"]["metadata"] = {
                    {"entity_type", entity_type},
                    {"attribute", fsmd.attribute},
                    {"value", fsmd.value},
                    {"units", fsmd.units}
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
