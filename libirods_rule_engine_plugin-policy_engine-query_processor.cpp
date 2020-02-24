
#include "policy_engine.hpp"

#include "irods_query.hpp"
#include "thread_pool.hpp"
#include "query_processor.hpp"

#include "json.hpp"

namespace {
    namespace pe = irods::policy_engine;

    const std::string irods_token_current_time{"IRODS_TOKEN_CURRENT_TIME"};
    const std::string irods_token_lifetime{"IRODS_TOKEN_LIFETIME"};

    irods::error query_processor_policy(const pe::context& ctx)
    {
        try {

            std::string query_string{ctx.parameters.at("query_string")};
            int         query_limit{ctx.parameters.at("query_limit")};
            auto        query_type{irods::query<rsComm_t>::convert_string_to_query_type(ctx.parameters.at("query_type"))};
            std::string policy_to_invoke{ctx.parameters.at("policy_to_invoke")};
            int number_of_threads{4};
            if(!ctx.parameters["number_of_threads"].empty()) {
                number_of_threads = ctx.parameters["number_of_threads"];
            }

            size_t start_pos = query_string.find(irods_token_lifetime);
            if(start_pos != std::string::npos) {

                auto lifetime = irods::extract_object_parameter<int>("lifetime", ctx.configuration);

                // add config to QP for deta T
                // query processor could know about lifetimes?
                query_string.replace(
                    start_pos,
                    irods_token_lifetime.length(),
                    std::to_string(std::time(nullptr) - lifetime));
            }

            using json       = nlohmann::json;
            using result_row = irods::query_processor<rsComm_t>::result_row;

            auto job = [&](const result_row& _results) {
                auto res_arr = json::array();
                for(auto& r : _results) {
                    res_arr.push_back(r);
                }

                std::string params = res_arr.dump();
                std::string config = ctx.configuration.dump();
                std::list<boost::any> arguments;
                arguments.push_back(boost::any(std::ref(params)));
                arguments.push_back(boost::any(std::ref(config)));
                irods::invoke_policy(ctx.rei, policy_to_invoke, arguments);
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
                           "query failed for [%d] objects for query [%s]")
                           % errors.size()
                           % query_string.c_str());
            }

        }
        catch(const irods::exception& e) {
            if(CAT_NO_ROWS_FOUND == e.code()) {
                // if nothing of interest is found, thats not an error
            }
            else {
                irods::exception_to_rerror(
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
