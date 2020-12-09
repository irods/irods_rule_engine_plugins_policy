#include "policy_composition_framework_policy_engine.hpp"
#include "policy_composition_framework_parameter_capture.hpp"
#include "policy_composition_framework_configuration_manager.hpp"

#include "parameter_substitution.hpp"

#include "apiNumber.h"
#include "irods_server_api_call.hpp"
#include "irods_resource_manager.hpp"
#include "irods_hierarchy_parser.hpp"

#include "json.hpp"

#include <algorithm>
#include <iostream>

extern irods::resource_manager resc_mgr;

namespace {

    // clang-format off
    namespace pc                  = irods::policy_composition;
    namespace pe                  = irods::policy_composition::policy_engine;
    using     string_vector       = std::vector<std::string>;
    using     string_tuple_vector = std::vector<std::tuple<std::string, std::string>>;
    // clang-format on

    namespace retention_mode {
        static const std::string remove_all{"remove_all_replicas"};
        static const std::string trim_single{"trim_single_replica"};
    };

    bool mode_is_supported(const std::string& m)
    {
        return (m == retention_mode::remove_all || m == retention_mode::trim_single);
    }

    auto get_replica_number_for_resource(
          rsComm_t*          comm
        , const std::string& logical_path
        , const std::string& source_resource)
    {
        namespace fs = irods::experimental::filesystem;

        fs::path path{logical_path};
        const auto coll_name = path.parent_path();
        const auto data_name = path.object_name();

        // query for list of all participating resources
        auto qstr{boost::str(boost::format(
                  "SELECT DATA_REPL_NUM WHERE COLL_NAME = '%s' AND DATA_NAME = '%s' AND RESC_NAME = '%s'")
                  % coll_name.string()
                  % data_name.string()
                  % source_resource)};

        irods::query qobj{comm, qstr};

        return qobj.size() > 0 ? qobj.front()[0] : "INVALID_REPLICA_NUMBER";

    } // get_replica_number_for_resource

    int remove_data_object(
          int                api_index
        , rsComm_t*          comm
        , const std::string& user_name
        , const std::string& logical_path
        , const std::string& source_resource = {})
    {
        dataObjInp_t obj_inp{};
        memset(&obj_inp, 0, sizeof(obj_inp));
        rstrcpy(obj_inp.objPath, logical_path.c_str(), sizeof(obj_inp.objPath));

        if(comm->clientUser.authInfo.authFlag >= LOCAL_PRIV_USER_AUTH) {
            addKeyVal(&obj_inp.condInput, ADMIN_KW, "true" );
        }

        addKeyVal(&obj_inp.condInput, COPIES_KW, "1" );

        std::string hier{}, repl_num{};
        if(!source_resource.empty()) {
            repl_num = get_replica_number_for_resource(comm, logical_path, source_resource);
            addKeyVal(&obj_inp.condInput, REPL_NUM_KW, repl_num.c_str());

            irods::error err = resc_mgr.get_hier_to_root_for_resc(source_resource, hier);
            addKeyVal(&obj_inp.condInput, RESC_HIER_STR_KW, hier.c_str());
        }

        auto trim_fcn = [&](auto& comm) {
            return irods::server_api_call(api_index, &comm, &obj_inp);
        };

        return pc::exec_as_user(*comm, user_name, trim_fcn);

    } // remove_data_object

    auto get_leaf_resources_for_object(rsComm_t* comm, const std::string& logical_path)
    {
        namespace fs = irods::experimental::filesystem;

        fs::path path{logical_path};
        const auto coll_name = path.parent_path();
        const auto data_name = path.object_name();

        // query for list of all participating resources
        auto qstr{boost::str(boost::format(
                  "SELECT RESC_NAME WHERE COLL_NAME = '%s' AND DATA_NAME = '%s'")
                  % coll_name.string()
                  % data_name.string())};

        irods::query qobj{comm, qstr};

        string_vector resources{};
        for(auto r : qobj) {
            resources.push_back(r[0]);
        }

        return resources;

    } // get_leaf_resources_for_object

    auto get_leaf_resource_for_root(
        rsComm_t* comm
      , const std::string& source_resource
      , const std::string& logical_path)
    {
        namespace fs = irods::experimental::filesystem;

        fs::path path{logical_path};
        const auto coll_name = path.parent_path();
        const auto data_name = path.object_name();

        auto leaf_bundle = pe::compute_leaf_bundle(source_resource);

        auto qstr{boost::str(boost::format(
                  "SELECT RESC_NAME WHERE COLL_NAME = '%s' AND DATA_NAME = '%s' AND RESC_ID IN (%s)")
                  % coll_name.string()
                  % data_name.string()
                  % leaf_bundle)};

        irods::query qobj{comm, qstr};

        return qobj.size() > 0 ? qobj.front()[0] : "EMPTY_RESC_NAME";

    } // get_leaf_resource_for_root

    auto get_root_resources_for_leaves(rsComm_t* comm, const string_vector& leaf_resources)
    {
        std::vector<std::tuple<std::string, std::string>> roots_and_leaves;
        for(auto&& l : leaf_resources) {
            std::string hier{};
            irods::error err = resc_mgr.get_hier_to_root_for_resc(l, hier);

            irods::hierarchy_parser p(hier);
            roots_and_leaves.push_back(std::make_tuple(p.first_resc(), l));
        }

        return roots_and_leaves;

    } // get_root_resources_for_leaves

    auto filter_roots_and_leaves_by_whitelist(
        const string_vector&       whitelist
      , const string_tuple_vector& roots_and_leaves)
    {
        if(whitelist.empty()) {
            return roots_and_leaves;
        }

        string_tuple_vector tmp{};
        for(auto&& rl : roots_and_leaves) {
            if(std::find(whitelist.begin(), whitelist.end(), std::get<0>(rl)) != whitelist.end()) {
                tmp.push_back(rl);
            }
        }

        return tmp;

    } // filter_roots_and_leaves_by_whitelist

    bool resource_has_preservation_metadata(
          rsComm_t*            comm
        , const std::string&   attribute
        , const std::string&   resource)
    {
        auto qstr = boost::str(boost::format(
                    "SELECT META_RESC_ATTR_VALUE WHERE RESC_NAME = '%s' AND META_RESC_ATTR_NAME = '%s'")
                    % resource
                    % attribute);
        irods::query qobj{comm, qstr};

        return qobj.size() != 0;

    } // resource_has_preservation_metadata

    auto filter_roots_and_leaves_by_preservation_metadata(
          rsComm_t*                  comm
        , const std::string&         attribute
        , const string_tuple_vector& roots_and_leaves)
    {
        string_tuple_vector tmp{};
        for(auto&& rl : roots_and_leaves) {
            if(!resource_has_preservation_metadata(comm, attribute, std::get<0>(rl))) {
                tmp.push_back(rl);
            }
        }

        return tmp;

    } // filter_roots_and_leaves_by_preservation_metadata

    auto determine_resource_list_for_unlink(
          rsComm_t*            comm
        , const std::string&   attribute
        , const std::string&   logical_path
        , const string_vector& whitelist)
    {
        // need to convert leaves to roots and then determine if
        // 1. it is in the white list
        // 2. if it has preservation metadata

        auto leaf_resources = get_leaf_resources_for_object(comm, logical_path);
        auto roots_and_leaves = get_root_resources_for_leaves(comm, leaf_resources);
        roots_and_leaves = filter_roots_and_leaves_by_whitelist(whitelist, roots_and_leaves);
        roots_and_leaves = filter_roots_and_leaves_by_preservation_metadata(comm, attribute, roots_and_leaves);

        // gather remaining leaves
        string_vector tmp{};
        for(auto&& rl : roots_and_leaves) {
            tmp.push_back(std::get<1>(rl));
        }

        // if identical to original list then we unlink, not trim
        auto unlink = (leaf_resources == tmp);

        return std::make_tuple(unlink, tmp);

    } // determine_resource_list_for_unlink

    auto object_can_be_trimmed(
        rsComm_t*            comm
      , const std::string&   attribute
      , const std::string&   source_resource
      , const string_vector& whitelist)
    {
        if(!whitelist.empty()) {
            if(std::find(whitelist.begin(), whitelist.end(), source_resource) == whitelist.end()) {
                return false;
            }
        }

        return !resource_has_preservation_metadata(comm, attribute, source_resource);

    } // object_can_be_trimmed

    irods::error data_retention_policy(const pe::context& ctx)
    {
        auto log_actions = pe::get_log_errors_flag(ctx.parameters, ctx.configuration);

        if(log_actions) {
            std::cout << "irods_policy_data_retention :: parameters " << ctx.parameters.dump(4) << "\n";
        }

        pe::configuration_manager cfg_mgr{ctx.instance_name, ctx.configuration};

        auto mode = cfg_mgr.get<std::string>("mode", "");
        if(!mode_is_supported(mode)) {
            return ERROR(SYS_INVALID_INPUT_PARAM,
                         boost::format("retention mode is not supported [%s]")
                         % mode);
        }

        auto [user_name, logical_path, source_resource, destination_resource] =
            capture_parameters(ctx.parameters, tag_first_resc);

        auto comm      = ctx.rei->rsComm;
        auto whitelist = cfg_mgr.get("resource_white_list", json::array());
        auto attribute = cfg_mgr.get("attribute", "irods::retention::preserve_replicas");

        if(mode == retention_mode::remove_all) {
            auto [unlink, resources_to_remove] =
            determine_resource_list_for_unlink(
                  comm
                , attribute
                , logical_path
                , whitelist);

            // removing all replicas requires a call to unlink, cannot trim
            if(unlink) {
                if(log_actions) { std::cout << "irods_policy_data_retention :: unlinking [" << logical_path << "] as user [" << user_name << "]\n"; }

                const auto ret = remove_data_object(
                                       DATA_OBJ_UNLINK_AN
                                     , comm
                                     , user_name
                                     , logical_path);
                if(ret < 0) {
                     return ERROR(
                               ret,
                               boost::format("failed to remove [%s] from [%s]")
                               % logical_path
                               % source_resource);
                }

            }
            // trim a specific list of replicas determined by policy
            else {
                for(const auto& src : resources_to_remove) {
                    if(log_actions) {
                        std::cout << "irods_policy_data_retention :: trimming replica ["
                                  << logical_path << "] from [" << src << "] as user [" << user_name << "]\n";
                    }

                    const auto ret = remove_data_object(
                                           DATA_OBJ_TRIM_AN
                                         , comm
                                         , user_name
                                         , logical_path
                                         , src);
                    if(ret < 0) {
                         return ERROR(
                                   ret,
                                   boost::format("failed to remove [%s] from [%s]")
                                   % logical_path
                                   % src);
                    }
                } // for src
            }
        }
        // trim single replica
        else {
            if(object_can_be_trimmed(comm, attribute, source_resource, whitelist)) {
                auto leaf_name = get_leaf_resource_for_root(comm, source_resource, logical_path);
                if(log_actions) {
                    std::cout << "irods_policy_data_retention :: trimming single replica ["
                              << logical_path << "] from [" << leaf_name << "] as user [" << user_name << "]\n";
                }

                const auto ret = remove_data_object(
                                       DATA_OBJ_TRIM_AN
                                     , comm
                                     , user_name
                                     , logical_path
                                     , leaf_name);
                if(ret < 0) {
                     return ERROR(
                               ret,
                               boost::format("failed to remove [%s] from [%s]")
                               % logical_path
                               % source_resource);
                }
            }
        }

        return SUCCESS();

    } // data_retention_policy

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
               , "irods_policy_data_retention"
               , usage
               , data_retention_policy);

} // plugin_factory
