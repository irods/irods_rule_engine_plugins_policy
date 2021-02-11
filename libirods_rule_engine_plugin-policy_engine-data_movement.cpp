
#include "policy_composition_framework_policy_engine.hpp"
#include "policy_composition_framework_parameter_capture.hpp"
#include "policy_composition_framework_configuration_manager.hpp"
#include "json.hpp"

namespace {

    // clang-format off
    namespace pc = irods::policy_composition;
    namespace kw = irods::policy_composition::keywords;
    namespace pe = irods::policy_composition::policy_engine;
    // clang-format on

    using invoke_policy_type = std::function<void(ruleExecInfo_t*, const std::string&, std::list<boost::any>)>;

    void apply_data_replication_policy(
          ruleExecInfo_t*    _rei
        , pe::arg_type _parameters
        , pe::arg_type _configuration
        , pe::arg_type _out)
    {
        std::list<boost::any> args;
        args.push_back(boost::any(_parameters));
        args.push_back(boost::any(_configuration));
        args.push_back(boost::any(_out));
        pc::invoke_policy(_rei, "irods_policy_data_replication", args);

    } // apply_data_replication_policy

    void apply_data_verification_policy(
          ruleExecInfo_t*    _rei
        , pe::arg_type _parameters
        , pe::arg_type _configuration
        , pe::arg_type _out)
    {
        std::list<boost::any> args;
        args.push_back(boost::any(_parameters));
        args.push_back(boost::any(_configuration));
        args.push_back(boost::any(_out));
        pc::invoke_policy(_rei, "irods_policy_data_verification", args);

    } // apply_data_verification_policy

    void apply_data_retention_policy(
          ruleExecInfo_t*    _rei
        , pe::arg_type _parameters
        , pe::arg_type _configuration
        , pe::arg_type _out)
    {
        std::list<boost::any> args;
        args.push_back(boost::any(_parameters));
        args.push_back(boost::any(_configuration));
        args.push_back(boost::any(_out));
        pc::invoke_policy(_rei, "irods_policy_data_retention", args);

    } // apply_data_retention_policy

    irods::error data_movement_policy(const pe::context& _ctx, pe::arg_type _out)
    {
        nlohmann::json source_to_destination_map;

        pe::configuration_manager cfg_mgr{_ctx.instance_name, _ctx.configuration};

        auto [user_name, logical_path, source_resource, destination_resource] =
            capture_parameters(_ctx.parameters, tag_first_resc);

        if(destination_resource.empty()) {
            destination_resource = cfg_mgr.get(kw::destination_resource, "");
            if(destination_resource.empty()) {
                auto source_to_destination_map = cfg_mgr.get("source_to_destination_map", json::array());

                if(source_to_destination_map.empty()) {
                    return ERROR(
                               SYS_INVALID_INPUT_PARAM,
                               boost::format("%s destination_resource or source_to_destination_map are not configured")
                               % _ctx.instance_name);
                }

                if(source_to_destination_map.find(source_resource) == source_to_destination_map.end()) {
                    return SUCCESS();
                }

                destination_resource = source_to_destination_map.at(source_resource);
            }

        }

        nlohmann::json params = {
              { kw::user_name, user_name }
            , { kw::logical_path, logical_path }
            , { kw::source_resource, source_resource }
            , { kw::destination_resource, destination_resource }
        };

        auto pstr = params.dump();
        auto cstr = _ctx.configuration.dump();

        apply_data_replication_policy(
              _ctx.rei
            , &pstr
            , &cstr
            , _out);

        apply_data_verification_policy(
              _ctx.rei
            , &pstr
            , &cstr
            , _out);

        apply_data_retention_policy(
              _ctx.rei
            , &pstr
            , &cstr
            , _out);

        return SUCCESS();

    } // data_movement_policy

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
               , "irods_policy_data_movement"
               , usage
               , data_movement_policy);

} // plugin_factory
