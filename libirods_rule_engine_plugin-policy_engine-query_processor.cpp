
#include "policy_composition_framework_policy_engine.hpp"
#include "policy_composition_framework_parameter_capture.hpp"
#include "policy_composition_framework_configuration_manager.hpp"

#include "parameter_substitution.hpp"

#include "thread_pool.hpp"
#include "query_processor.hpp"

#include "json.hpp"
#include "fmt/format.h"

namespace {

    // clang-format off
    namespace pe   = irods::policy_composition::policy_engine;
    namespace ipc  = irods::policy_composition;
    namespace fs   = irods::experimental::filesystem;
    namespace fsvr = irods::experimental::filesystem::server;
    // clang-format on


    irods::error query_processor_policy(const pe::context& ctx, pe::arg_type out)
    {
        try {
            pe::configuration_manager cfg_mgr{ctx.instance_name, ctx.configuration};

            auto number_of_threads = cfg_mgr.get<int>("number_of_threads", 4);
            auto query_limit = cfg_mgr.get<int>("query_limit", 0);
            auto query_type_string = cfg_mgr.get<std::string>("query_type", "general");

            auto query_type = irods::query<rsComm_t>::convert_string_to_query_type(query_type_string);

            auto query_string = cfg_mgr.get<std::string>("query_string", "");
            if(query_string.empty()) {
                return ERROR(SYS_INVALID_INPUT_PARAM, "irods_policy_query_processor - empty query string");
            }

            auto policy_to_invoke = cfg_mgr.get<std::string>("policy_to_invoke", "");
            if(policy_to_invoke.empty()) {
                return ERROR(SYS_INVALID_INPUT_PARAM, "irods_policy_query_processor - empty policy_to_invoke");
            }

            if(ctx.parameters.contains("query_results")) {
                pe::replace_positional_tokens(
                    query_string
                  , ctx.parameters.at("query_results").get<std::vector<std::string>>());
            }

            std::string user_name{}, logical_path{}, source_resource{}, destination_resource{};
            std::tie(user_name, logical_path, source_resource, destination_resource) = capture_parameters(ctx.parameters, tag_first_resc);

            auto& comm = *ctx.rei->rsComm;

            auto [data_name, coll_name] = pe::split_logical_path(comm, logical_path);

            std::vector<std::string> values = {std::to_string(std::time(nullptr)), "0", user_name, coll_name, data_name, source_resource, destination_resource};

            time_t lifetime{};
            if(ctx.configuration.contains("lifetime")) {
                auto ltp = ctx.configuration.at("lifetime");
                if(pe::paramter_requires_query_substitution(ltp)) {
                    auto tmp = pe::perform_query_substitution<time_t>(comm, ltp, values);
                    lifetime = std::time(nullptr) - tmp;
                }
                else {
                    auto tmp = ctx.configuration.at("lifetime").get<time_t>();
                    lifetime = std::time(nullptr) - tmp;
                }
            }

            values[1] = std::to_string(lifetime);

            pe::parse_and_replace_query_string_tokens(query_string, values);

            using json       = nlohmann::json;
            using result_row = irods::query_processor<rsComm_t>::result_row;

            json params_to_pass{ctx.parameters};

            auto job = [&](const result_row& _results) {
                auto res_arr = json::array();
                for(auto& r : _results) {
                    res_arr.push_back(r);
                }
                params_to_pass["query_results"] = res_arr;
                std::string params_str = params_to_pass.dump();

                std::string config_str{};
                if(ctx.configuration.contains("configuration")) {
                   config_str = ctx.configuration.at("configuration").dump();
                }

                std::list<boost::any> arguments;
                arguments.push_back(boost::any(std::ref(params_str)));
                arguments.push_back(boost::any(std::ref(config_str)));
                ipc::invoke_policy(ctx.rei, policy_to_invoke, arguments);
            }; // job

            irods::thread_pool thread_pool{number_of_threads};
            irods::query_processor<rsComm_t> qp(query_string, job, query_limit, query_type);
            auto future = qp.execute(thread_pool, *ctx.rei->rsComm);
            auto errors = future.get();
            if(errors.size() > 0) {
                for(auto& e : errors) {
                    rodsLog(
                        LOG_ERROR,
                        "query failed [%d]::[%s]",
                        std::get<0>(e),
                        std::get<1>(e).c_str());
                }

                return ERROR(
                           SYS_INVALID_OPR_TYPE,
                           boost::format(
                           "query processor encountered an error for [%d] rows for query [%s]")
                           % errors.size()
                           % query_string.c_str());
            }

            if(0 == qp.size() && ctx.configuration.contains("default_results_when_no_rows_found")) {
                result_row res;
                for(auto& r : ctx.configuration.at("default_results_when_no_rows_found")) {
                    res.push_back(r.get<std::string>());
                }

                job(res);

                if(errors.size() > 0) {
                    for(auto& e : errors) {
                        rodsLog(
                            LOG_ERROR,
                            "query failed [%d]::[%s]",
                            std::get<0>(e),
                            std::get<1>(e).c_str());
                    }

                    return ERROR(
                               SYS_INVALID_OPR_TYPE,
                               boost::format(
                               "query processor encountered an error for [%d] rows for query [%s]")
                               % errors.size()
                               % query_string.c_str());
                }
            }
        }
        catch(const irods::exception& e) {
            if(CAT_NO_ROWS_FOUND == e.code()) {
                // if nothing of interest is found, thats not an error
            }
            else {
                ipc::exception_to_rerror(
                    e, ctx.rei->rsComm->rError);
                return ERROR(
                          e.code(),
                          e.what());
            }
        }

        return SUCCESS();

    } // query_processor_policy

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
               , "irods_policy_query_processor"
               , usage
               , query_processor_policy);
} // plugin_factory
