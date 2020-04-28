
#include "policy_engine.hpp"
#include "policy_engine_parameter_capture.hpp"
#include "policy_engine_configuration_manager.hpp"
#include "json.hpp"

namespace pe = irods::policy_engine;

namespace {
    using invoke_policy_type = std::function<void(ruleExecInfo_t*, const std::string&, std::list<boost::any>)>;

    void apply_data_replication_policy(
          ruleExecInfo_t*    _rei
        , pe::arg_type _parameters
        , pe::arg_type _configuration)
    {
        std::list<boost::any> args;
        args.push_back(boost::any(_parameters));
        args.push_back(boost::any(_configuration));
        irods::invoke_policy(_rei, "irods_policy_data_replication", args);

    } // apply_data_replication_policy

    void apply_data_verification_policy(
          ruleExecInfo_t*    _rei
        , pe::arg_type _parameters
        , pe::arg_type _configuration)
    {
        std::list<boost::any> args;
        args.push_back(boost::any(_parameters));
        args.push_back(boost::any(_configuration));
        irods::invoke_policy(_rei, "irods_policy_data_verification", args);

    } // apply_data_verification_policy

    void apply_data_retention_policy(
          ruleExecInfo_t*    _rei
        , pe::arg_type _parameters
        , pe::arg_type _configuration)
    {
        std::list<boost::any> args;
        args.push_back(boost::any(_parameters));
        args.push_back(boost::any(_configuration));
        irods::invoke_policy(_rei, "irods_policy_data_retention", args);

    } // apply_data_retention_policy

    irods::error data_movement_policy(const pe::context& ctx)
    {
        nlohmann::json source_to_destination_map;

        pe::configuration_manager cfg_mgr{ctx.instance_name, ctx.configuration};

        std::string user_name{}, logical_path{}, source_resource{}, destination_resource{};

        std::tie(user_name, logical_path, source_resource, destination_resource) =
            capture_parameters(ctx.parameters, tag_first_resc);

        if(destination_resource.empty()) {
            irods::error err;
            std::tie(err, destination_resource) = cfg_mgr.get_value(
                                                      "destination_resource", "");
            if(!err.ok()) {
                std::tie(err, source_to_destination_map) =
                    cfg_mgr.get_value(
                        "source_to_destination_map",
                        source_to_destination_map);

                if(source_to_destination_map.empty()) {
                    return ERROR(
                               SYS_INVALID_INPUT_PARAM,
                               boost::format("%s destination_resource or source_to_destination_map are not configured")
                               % ctx.instance_name);
                }

                if(source_to_destination_map.find(source_resource) ==
                   source_to_destination_map.end()) {
                    return SUCCESS();
                }

                destination_resource = source_to_destination_map.at(source_resource);
            }

        }

        nlohmann::json params = {
              { "user_name", user_name }
            , { "logical_path", logical_path }
            , { "source_resource", source_resource }
            , { "destination_resource", destination_resource }
        };

        auto pstr = params.dump();
        auto cstr = ctx.configuration.dump();

        apply_data_replication_policy(
              ctx.rei
            , pstr
            , cstr);

        apply_data_verification_policy(
              ctx.rei
            , pstr
            , cstr);

        apply_data_retention_policy(
              ctx.rei
            , pstr
            , cstr);

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
