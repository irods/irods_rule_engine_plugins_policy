
#include "policy_engine.hpp"
#include "policy_engine_parameter_capture.hpp"
#include "policy_engine_configuration_manager.hpp"
#include "parameter_substitution.hpp"

#include "json.hpp"

#include "irods_query.hpp"

namespace {
    namespace pe   = irods::policy_engine;
    namespace fs   = irods::experimental::filesystem;
    namespace fsvr = irods::experimental::filesystem::server;

    using fsp  = fs::path;
    using json = nlohmann::json;

    irods::error event_generator_resource_metadata(const pe::context& ctx)
    {
        auto comm{ctx.rei->rsComm};

        pe::configuration_manager cfg_mgr{ctx.instance_name, ctx.configuration};

        auto policies_to_invoke = cfg_mgr.get("policies_to_invoke", json::array());
        if(policies_to_invoke.empty()) {
            return ERROR(
                       SYS_INVALID_INPUT_PARAM,
                       "event_generator_resource_metadata - policies_to_invoke is empty");
        }

        json conditional{};
        if(ctx.configuration.contains("conditional") &&
           ctx.configuration.at("conditional").contains("metadata")) {
            conditional = ctx.configuration.at("conditional").at("metadata");
        }
        else {
            return ERROR(
                        SYS_INVALID_INPUT_PARAM,
                        "event_generator-resource_metadata - missing conditional metadata");
        }

        if(ctx.parameters.contains("query_results")) {
            auto results = ctx.parameters.at("query_results").get<std::vector<std::string>>();
            auto str     = conditional.dump();
            pe::replace_positional_tokens(str, results);
            conditional = json::parse(str);
        }
        else {
            // ctx.parameters.contains("metadata");
        }

        std::string qstr{"SELECT RESC_NAME, ORDER(META_RESC_ATTR_UNITS) WHERE"};

        if(conditional.contains("attribute")) {
            qstr += " META_RESC_ATTR_NAME = '" + conditional.at("attribute").get<std::string>() + "'";
        }

        if(conditional.contains("value")) {
            if(!qstr.empty()) { qstr += " AND "; }
            qstr += " META_RESC_ATTR_VALUE = '" + conditional.at("value").get<std::string>() + "'";
        }

        if(conditional.contains("units")) {
            if(!qstr.empty()) { qstr += " AND "; }
            qstr += " META_RESC_ATTR_UNITS = '" + conditional.at("units").get<std::string>() + "'";
        }

        for(auto& policy : policies_to_invoke) {
            std::string policy_name{policy["policy"]};

            json tmp_params{};
            //if(policy.contains("parameters")) {
            //    tmp_params = policy.at("parameters");
            //}
            //else {
                tmp_params = ctx.parameters;
            //}

            json tmp_config{};
            if(policy.contains("configuration")) {
                tmp_config = policy.at("configuration");
            }
            else {
                tmp_config = ctx.configuration;
            }

            irods::query<rsComm_t> qobj{ctx.rei->rsComm, qstr};
            std::vector<std::string> resc_names;
            for(auto r : qobj) {
                resc_names.push_back(r[0]);
            }

            if(resc_names.empty()) {
                rodsLog(LOG_ERROR, "%s :: zero requlst for query [%s]", __FUNCTION__, qstr.c_str());
                return SUCCESS();
            }

            for(auto i = 0; i < resc_names.size()-1; ++i) {
                tmp_params["source_resource"] = resc_names[i];
                if(resc_names.size() > 1) {
                    tmp_params["destination_resource"] = resc_names[i+1];
                }

                std::string params{tmp_params.dump()};
                std::string config{tmp_config.dump()};

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

    } // event_generator_resource_metadata
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
                "name" :  "event_handler-data_resource_modified",
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
               , "irods_policy_event_generator_resource_metadata"
               , usage
               , event_generator_resource_metadata);
} // plugin_factory
