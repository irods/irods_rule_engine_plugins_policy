
#include "irods_re_plugin.hpp"
#include "irods_re_ruleexistshelper.hpp"
#include "irods_plugin_context.hpp"
#include "irods_hierarchy_parser.hpp"
#include "event_handler_utilities.hpp"
#include "rule_engine_plugin_configuration_json.hpp"
#include "rcMisc.h"

#include <boost/any.hpp>
#include "objDesc.hpp"
#include "physPath.hpp"
#include "bulkDataObjReg.h"

#include "boost/lexical_cast.hpp"

#include "policy_engine_utilities.hpp"

#include <typeinfo>
#include <algorithm>

#include "json.hpp"
using json = nlohmann::json;

// Persistent L1 File Descriptor Table
extern l1desc_t L1desc[NUM_L1_DESC];

namespace {
    const std::map<std::string, std::string> peps_to_events{
        { "pep_api_bulk_data_obj_put_pre",        "CREATE" },
        { "pep_api_data_obj_chksum_pre",          "CHECKSUM" },
        { "pep_api_data_obj_copy_pre",            "COPY" },
        { "pep_api_data_obj_create_and_stat_pre", "CREATE" },
        { "pep_api_data_obj_create_pre",          "CREATE" },
        { "pep_api_data_obj_get_pre",             "GET" },
        { "pep_api_data_obj_lseek_pre",           "SEEK" },
        { "pep_api_data_obj_phymv_pre",           "REPLICATION" },
        { "pep_api_data_obj_put_pre",             "PUT" },
        { "pep_api_data_obj_rename_pre",          "RENAME" },
        { "pep_api_data_obj_repl_pre",            "REPLICATION" },
        { "pep_api_data_obj_trim_pre",            "TRIM" },
        { "pep_api_data_obj_truncate_pre",        "TRUNCATE" },
        { "pep_api_data_obj_unlink_pre",          "UNLINK" },
        { "pep_api_phy_path_reg_pre",             "REGISTER" },

        { "pep_api_bulk_data_obj_put_post",        "CREATE" },
        { "pep_api_data_obj_chksum_post",          "CHECKSUM" },
        { "pep_api_data_obj_copy_post",            "COPY" },
        { "pep_api_data_obj_create_and_stat_post", "CREATE" },
        { "pep_api_data_obj_create_post",          "CREATE" },
        { "pep_api_data_obj_get_post",             "GET" },
        { "pep_api_data_obj_lseek_post",           "SEEK" },
        { "pep_api_data_obj_phymv_post",           "REPLICATION" },
        { "pep_api_data_obj_put_post",             "PUT" },
        { "pep_api_data_obj_rename_post",          "RENAME" },
        { "pep_api_data_obj_repl_post",            "REPLICATION" },
        { "pep_api_data_obj_trim_post",            "TRIM" },
        { "pep_api_data_obj_truncate_post",        "TRUNCATE" },
        { "pep_api_data_obj_unlink_post",          "UNLINK" },
        { "pep_api_phy_path_reg_post",             "REGISTER" },
    };

    std::unique_ptr<irods::plugin_configuration_json> config;
    std::map<int, json> objects_in_flight;
    std::string plugin_instance_name{};
    std::set<std::string> consumed_policy_enforcement_points{
                                    "pep_resource_resolve_hierarchy_pre",
                                    "pep_api_data_obj_open_pre",
                                    "pep_api_data_obj_close_pre",

                                    "pep_resource_resolve_hierarchy_post",
                                    "pep_api_data_obj_open_post",
                                    "pep_api_data_obj_close_post"};

    auto rule_name_is_supported(const std::string& _rule_name) {
        return (consumed_policy_enforcement_points.find(_rule_name) !=
                consumed_policy_enforcement_points.end());
    } // rule_name_is_supported

    std::string hierarchy_resolution_operation{};

    void invoke_policies_for_object(
        ruleExecInfo_t*    _rei,
        const std::string& _event,
        const std::string& _rule_name,
        const json&        _obj_json) {
        auto policies_to_invoke{config->plugin_configuration["policies_to_invoke"]};

        if(policies_to_invoke.empty()) {
            rodsLog(
                LOG_ERROR,
                "[%s] is missing configuration",
                plugin_instance_name.c_str());
            return;
        }

        std::list<boost::any> args;
        for(auto& policy : policies_to_invoke) {
            auto pre_post = policy["active_policy_clauses"];
            if(pre_post.empty()) {
                continue;
            }

            for(auto& p : pre_post) {
                std::string suffix{"_"}; suffix += p;
                if(_rule_name.find(suffix) != std::string::npos) {
                    auto ops = policy["events"];
                    for(auto& op : ops) {

                        std::string upper_operation{op};
                        std::transform(upper_operation.begin(),
                                       upper_operation.end(),
                                       upper_operation.begin(),
                                       ::toupper);
                        if(upper_operation != _event) {
                            continue;
                        }

                        auto pnm{policy["policy"]};

                        json, cfg(), pam{};

                        if(policy.contains("configuration")) {
                            cfg = policy.at("configuration");
                        }

                        if(policy.contains("parameters")) {
                            pam = policy.at("parameters");
                        }

                        pam += _obj_json;

                        std::string params{pam.dump()};
                        std::string config{cfg.dump()};

                        args.clear();
                        args.push_back(boost::any(std::ref(params)));
                        args.push_back(boost::any(std::ref(config)));

                        irods::invoke_policy(_rei, pnm, args);
                    } // for ops

                } // if suffix
            } // for pre_post
        } // for policy
    } // invoke_policies_for_object

    void seralize_bulk_put_object_parameters(
        ruleExecInfo_t*    _rei,
        const std::string& _rule_name,
        genQueryOut_t&     _attr_arr,
        keyValPair_t&      _cond_input) {
        const std::string event{hierarchy_resolution_operation};

        auto comm_obj = irods::serialize_rsComm_to_json(_rei->rsComm);

        auto obj_path = getSqlResultByInx(&_attr_arr, COL_DATA_NAME);
        if(!obj_path) {
            THROW(UNMATCHED_KEY_OR_INDEX, "missing object path");
        }

        auto offset = getSqlResultByInx(&_attr_arr, OFFSET_INX);
        if(!offset) {
            THROW(UNMATCHED_KEY_OR_INDEX, "missing offset");
        }

        std::vector<int> offset_int{};
        for (int i = 0; i < _attr_arr.rowCnt; ++i) {
            offset_int.push_back(atoi(&offset->value[offset->len * i]));
        }

        dataObjInp_t obj_inp{};
        obj_inp.condInput = _cond_input;
        for(int i = 0; i < _attr_arr.rowCnt; ++i) {
            rstrcpy(obj_inp.objPath,
                    &obj_path->value[obj_path->len * i],
                    sizeof(obj_inp.objPath));
            obj_inp.dataSize = i==0 ? offset_int[0] : offset_int[i]-offset_int[i-1];
            auto jobj = irods::serialize_dataObjInp_to_json(obj_inp);
            jobj["policy_enforcement_point"] = _rule_name;
            jobj["event"] = event;
            jobj["comm"] = comm_obj;
            invoke_policies_for_object(_rei, event, _rule_name, jobj);

        } // for i

    } // seralize_bulk_put_object_parameters

    void event_data_object_modified(
        const std::string&           _rule_name,
        ruleExecInfo_t*              _rei,
        const std::list<boost::any>& _arguments) {
        try {

            auto comm_obj = irods::serialize_rsComm_to_json(_rei->rsComm);

            if("pep_resource_resolve_hierarchy_pre"  == _rule_name ||
               "pep_resource_resolve_hierarchy_post" == _rule_name) {
                auto it = _arguments.begin();
                auto ins = boost::any_cast<std::string>(*it); ++it;
                auto ctx = boost::any_cast<irods::plugin_context>(*it); ++it;
                auto out = boost::any_cast<std::string*>(*it); ++it;
                auto opr = boost::any_cast<const std::string*>(*it); ++it;
                //auto hst = boost::any_cast<const std::string*>(*it); ++it;
                //auto prs = boost::any_cast<irods::hierarchy_parser*>(*it); ++it;
                //auto vte = boost::any_cast<float*>(*it); ++it;
                //std::string hier; prs->str(hier);
                hierarchy_resolution_operation = *opr;
            }
            else if("pep_api_bulk_data_obj_put_pre"  == _rule_name ||
                    "pep_api_bulk_data_obj_put_post" == _rule_name) {
                auto it = _arguments.begin();
                std::advance(it, 2);
                if(_arguments.end() == it) {
                    THROW(
                        SYS_INVALID_INPUT_PARAM,
                        "invalid number of arguments");
                }

                auto bulk_inp = boost::any_cast<bulkOprInp_t*>(*it);
                seralize_bulk_put_object_parameters(
                      _rei
                    , _rule_name
                    , bulk_inp->attriArray
                    , bulk_inp->condInput);
            }
            // all PEPs use the same signature
            else if("pep_api_data_obj_put_pre"     == _rule_name ||
                    "pep_api_data_obj_get_pre"     == _rule_name ||
                    "pep_api_data_obj_unlink_pre"  == _rule_name ||
                    "pep_api_data_obj_repl_pre"    == _rule_name ||
                    "pep_api_phy_path_reg_pre"     == _rule_name ||
                    "pep_api_data_obj_chksum_pre"  == _rule_name ||
                    "pep_api_data_obj_truncate_pre"== _rule_name ||

                    "pep_api_data_obj_put_post"    == _rule_name ||
                    "pep_api_data_obj_get_post"    == _rule_name ||
                    "pep_api_data_obj_unlink_post" == _rule_name ||
                    "pep_api_data_obj_repl_post"   == _rule_name ||
                    "pep_api_phy_path_reg_post"    == _rule_name ||
                    "pep_api_data_obj_truncate_pre"== _rule_name ||
                    "pep_api_data_obj_chksum_post" == _rule_name) {

                auto it = _arguments.begin();
                std::advance(it, 2);
                if(_arguments.end() == it) {
                    THROW(
                        SYS_INVALID_INPUT_PARAM,
                        "invalid number of arguments");
                }

                auto obj_inp = boost::any_cast<dataObjInp_t*>(*it);
                auto jobj = irods::serialize_dataObjInp_to_json(*obj_inp);

                const std::string event = [&]() -> const std::string {
                    const std::string& op = peps_to_events.at(_rule_name);
                    return op;
                }();

                jobj["policy_enforcement_point"] = _rule_name;
                jobj["event"] = event;
                jobj["comm"] = comm_obj;
                invoke_policies_for_object(_rei, event, _rule_name, jobj);
            }
            else if("pep_api_data_obj_lseek_pre"   == _rule_name ||
                    "pep_api_data_obj_lseek_post"  == _rule_name) {

                auto it = _arguments.begin();
                std::advance(it, 2);
                if(_arguments.end() == it) {
                    THROW(
                        SYS_INVALID_INPUT_PARAM,
                        "invalid number of arguments");
                }

                auto opened_inp = boost::any_cast<openedDataObjInp_t*>(*it);
                const auto l1_idx = opened_inp->l1descInx;
                auto jobj = objects_in_flight[l1_idx];

                const std::string event = [&]() -> const std::string {
                    const std::string& op = peps_to_events.at(_rule_name);
                    return op;
                }();

                jobj["policy_enforcement_point"] = _rule_name;
                jobj["event"] = event;
                jobj["comm"] = comm_obj;
                invoke_policies_for_object(_rei, event, _rule_name, jobj);

            }
            else if("pep_api_data_obj_copy_pre"  == _rule_name ||
                    "pep_api_data_obj_copy_post" == _rule_name) {
                auto it = _arguments.begin();
                std::advance(it, 2);
                if(_arguments.end() == it) {
                    THROW(
                        SYS_INVALID_INPUT_PARAM,
                        "invalid number of arguments");
                }

                const std::string event = peps_to_events.at(_rule_name);
                auto copy_inp = boost::any_cast<dataObjCopyInp_t*>(*it);

                auto src_jobj = irods::serialize_dataObjInp_to_json(copy_inp->srcDataObjInp);
                src_jobj["policy_enforcement_point"] = _rule_name;
                src_jobj["event"] = event;
                src_jobj["comm"] = comm_obj;
                invoke_policies_for_object(_rei, event, _rule_name, src_jobj);

                auto dst_jobj = irods::serialize_dataObjInp_to_json(copy_inp->destDataObjInp);
                dst_jobj["policy_enforcement_point"] = _rule_name;
                dst_jobj["event"] = event;
                dst_jobj["comm"] = comm_obj;
                invoke_policies_for_object(_rei, event, _rule_name, dst_jobj);

            }
            else if("pep_api_data_obj_rename_pre"  == _rule_name) {
                auto it = _arguments.begin();
                std::advance(it, 2);
                if(_arguments.end() == it) {
                    THROW(
                        SYS_INVALID_INPUT_PARAM,
                        "invalid number of arguments");
                }

                const std::string event = peps_to_events.at(_rule_name);
                auto copy_inp = boost::any_cast<dataObjCopyInp_t*>(*it);

                auto src_jobj = irods::serialize_dataObjInp_to_json(copy_inp->srcDataObjInp);
                src_jobj["policy_enforcement_point"] = _rule_name;
                src_jobj["event"] = event;
                src_jobj["comm"] = comm_obj;
                invoke_policies_for_object(_rei, event, _rule_name, src_jobj);
            }
            else if("pep_api_data_obj_rename_post" == _rule_name) {
                auto it = _arguments.begin();
                std::advance(it, 2);
                if(_arguments.end() == it) {
                    THROW(
                        SYS_INVALID_INPUT_PARAM,
                        "invalid number of arguments");
                }

                const std::string event = peps_to_events.at(_rule_name);
                auto copy_inp = boost::any_cast<dataObjCopyInp_t*>(*it);

                auto dst_jobj = irods::serialize_dataObjInp_to_json(copy_inp->destDataObjInp);
                dst_jobj["policy_enforcement_point"] = _rule_name;
                dst_jobj["event"] = event;
                dst_jobj["comm"] = comm_obj;
                invoke_policies_for_object(_rei, event, _rule_name, dst_jobj);
            }
            // uses the file descriptor table to track modify operations
            // only add an entry if the object is created or opened for write
            else if("pep_api_data_obj_open_pre"   == _rule_name ||
                    "pep_api_data_obj_create_pre" == _rule_name ||
                    "pep_api_data_obj_open_post"   == _rule_name ||
                    "pep_api_data_obj_create_post" == _rule_name) {
                auto it = _arguments.begin();
                std::advance(it, 2);
                if(_arguments.end() == it) {
                    THROW(
                        SYS_INVALID_INPUT_PARAM,
                        "invalid number of arguments");
                }

                auto obj_inp = boost::any_cast<dataObjInp_t*>(*it);

                int l1_idx{};
                json jobj{};
                try {
                    std::tie(l1_idx, jobj) = irods::get_index_and_json_from_obj_inp(obj_inp);
                    objects_in_flight[l1_idx] = jobj;
                }
                catch(const irods::exception& _e) {
                    rodsLog(
                       LOG_ERROR,
                       "irods::get_index_and_resource_from_obj_inp failed for [%s]",
                       obj_inp->objPath);
                }
            }
            // uses the tracked file descriptor table operations to invoke policy
            // if changes were actually made to the object
            else if("pep_api_data_obj_close_pre"  == _rule_name ||
                    "pep_api_data_obj_close_post" == _rule_name) {
                auto it = _arguments.begin();
                std::advance(it, 2);
                if(_arguments.end() == it) {
                    THROW(
                        SYS_INVALID_INPUT_PARAM,
                        "invalid number of arguments");
                }

                const auto opened_inp = boost::any_cast<openedDataObjInp_t*>(*it);
                const auto l1_idx = opened_inp->l1descInx;
                auto jobj = objects_in_flight[l1_idx];

                auto open_flags  = boost::lexical_cast<int>(std::string{jobj["open_flags"]});
                bool write_flag  = (open_flags & O_WRONLY || open_flags & O_RDWR);
                bool create_flag = (open_flags & O_CREAT);
                bool trunc_flag  = (open_flags & O_TRUNC);

                const auto event = [&]() -> const std::string {
                    if("CREATE" == hierarchy_resolution_operation) return "PUT";
                    else if("OPEN" == hierarchy_resolution_operation && write_flag) return "WRITE";
                    else if("OPEN" == hierarchy_resolution_operation && !write_flag) return "GET";
                    else return hierarchy_resolution_operation;
                }();

                jobj["policy_enforcement_point"] = _rule_name;
                jobj["event"] = event;
                jobj["comm"] = comm_obj;
                invoke_policies_for_object(_rei, event, _rule_name, jobj);

                if(trunc_flag) {
                    jobj["event"] = "TRUNCATE";
                    invoke_policies_for_object(_rei, event, _rule_name, jobj);
                }

            } // else if
        }
        catch(const std::invalid_argument& _e) {
            rodsLog(LOG_ERROR, "%s", _e.what());
        }
        catch(const boost::bad_any_cast& _e) {
            rodsLog(LOG_ERROR, "%s", _e.what());
        }
        catch(const boost::bad_lexical_cast& _e) {
            rodsLog(LOG_ERROR, "%s", _e.what());
        }
        catch(const irods::exception& _e) {
            rodsLog(LOG_ERROR, "%s", _e.what());
        }

    } // event_data_object_modified

} // namespace

irods::error start(
    irods::default_re_ctx&,
    const std::string& _instance_name ) {

    std::transform(
            std::begin(peps_to_events),
            std::end(peps_to_events),
            std::inserter(
                consumed_policy_enforcement_points,
                std::end(consumed_policy_enforcement_points)),
            [](auto& t) -> std::string { return t.first; });

    // capture plugin instance name
    plugin_instance_name = _instance_name;

    // load the plugin specific configuration for this instance
    config = std::make_unique<irods::plugin_configuration_json>(plugin_instance_name);

    // build a list of pep strings for the regexp
    std::string regex{};
    for( auto& s : consumed_policy_enforcement_points) {
        regex += s + " || ";
    }

    // trim trailing " || "
    regex = regex.substr(0, regex.size()-4);

    // register the event handler's peps as implemented by this plugin
    //RuleExistsHelper::Instance()->registerRuleRegex(regex);
    RuleExistsHelper::Instance()->registerRuleRegex("pep_api_.*");

    return SUCCESS();
}

irods::error stop(
    irods::default_re_ctx&,
    const std::string& ) {
    return SUCCESS();
}

irods::error rule_exists(
    irods::default_re_ctx&,
    const std::string& _rule_name,
    bool&              _return_value) {
    _return_value = rule_name_is_supported(_rule_name);
    return SUCCESS();
}

irods::error list_rules(
    irods::default_re_ctx&,
    std::vector<std::string>& _rules) {
    for( auto& s : consumed_policy_enforcement_points) {
        _rules.push_back(s);
    }
    return SUCCESS();
}

irods::error exec_rule(
    irods::default_re_ctx&,
    const std::string&     _rule_name,
    std::list<boost::any>& _arguments,
    irods::callback        _eff_hdlr) {
    ruleExecInfo_t* rei{};

    // capture an rei which provides the rsComm_t structure and rError
    const auto err = _eff_hdlr("unsafe_ms_ctx", &rei);
    if(!err.ok()) {
        // always return SYS_NOT_SUPPORTED given an error in an Event Handler
        // which allows the REPF to continue trying other plugins or rule bases
        return ERROR(SYS_NOT_SUPPORTED, err.result());
    }

    try {
        // given a specific PEP, invoke the event handler
        event_data_object_modified(_rule_name, rei, _arguments);
    }
    catch(const std::invalid_argument& _e) {
        // pass the exception to the rError stack to get the result
        // back to the client for forensics
        irods::exception_to_rerror(
            SYS_NOT_SUPPORTED,
            _e.what(),
            rei->rsComm->rError);
        return ERROR(
                   SYS_NOT_SUPPORTED,
                   _e.what());
    }
    catch(const boost::bad_any_cast& _e) {
        irods::exception_to_rerror(
            SYS_NOT_SUPPORTED,
            _e.what(),
            rei->rsComm->rError);
        return ERROR(
                   SYS_NOT_SUPPORTED,
                   _e.what());
    }
    catch(const irods::exception& _e) {
        irods::exception_to_rerror(
            _e,
            rei->rsComm->rError);
        return ERROR(
                   SYS_NOT_SUPPORTED,
                   _e.what());
    }

    // this code signals to the REPF that we were successfull but should continue
    // looking for further implementations of the same policy enforcement point
    return CODE(RULE_ENGINE_CONTINUE);

} // exec_rule

irods::error exec_rule_text(
    irods::default_re_ctx&,
    const std::string&,
    msParamArray_t*,
    const std::string&,
    irods::callback ) {
    return ERROR(
            RULE_ENGINE_CONTINUE,
            "exec_rule_text is not supported");
} // exec_rule_text

irods::error exec_rule_expression(
    irods::default_re_ctx&,
    const std::string&,
    msParamArray_t*,
    irods::callback) {
    return ERROR(
            RULE_ENGINE_CONTINUE,
            "exec_rule_expression is not supported");
} // exec_rule_expression

extern "C"
irods::pluggable_rule_engine<irods::default_re_ctx>* plugin_factory(
    const std::string& _inst_name,
    const std::string& _context ) {
    irods::pluggable_rule_engine<irods::default_re_ctx>* re =
        new irods::pluggable_rule_engine<irods::default_re_ctx>(
                _inst_name,
                _context);

    re->add_operation<
        irods::default_re_ctx&,
        const std::string&>(
            "start",
            std::function<
                irods::error(
                    irods::default_re_ctx&,
                    const std::string&)>(start));

    re->add_operation<
        irods::default_re_ctx&,
        const std::string&>(
            "stop",
            std::function<
                irods::error(
                    irods::default_re_ctx&,
                    const std::string&)>(stop));

    re->add_operation<
        irods::default_re_ctx&,
        const std::string&,
        bool&>(
            "rule_exists",
            std::function<
                irods::error(
                    irods::default_re_ctx&,
                    const std::string&,
                    bool&)>(rule_exists));

    re->add_operation<
        irods::default_re_ctx&,
        std::vector<std::string>&>(
            "list_rules",
            std::function<
                irods::error(
                    irods::default_re_ctx&,
                    std::vector<std::string>&)>(list_rules));

    re->add_operation<
        irods::default_re_ctx&,
        const std::string&,
        std::list<boost::any>&,
        irods::callback>(
            "exec_rule",
            std::function<
                irods::error(
                    irods::default_re_ctx&,
                    const std::string&,
                    std::list<boost::any>&,
                    irods::callback)>(exec_rule));

    re->add_operation<
        irods::default_re_ctx&,
        const std::string&,
        msParamArray_t*,
        const std::string&,
        irods::callback>(
            "exec_rule_text",
            std::function<
                irods::error(
                    irods::default_re_ctx&,
                    const std::string&,
                    msParamArray_t*,
                    const std::string&,
                    irods::callback)>(exec_rule_text));

    re->add_operation<
        irods::default_re_ctx&,
        const std::string&,
        msParamArray_t*,
        irods::callback>(
            "exec_rule_expression",
            std::function<
                irods::error(
                    irods::default_re_ctx&,
                    const std::string&,
                    msParamArray_t*,
                    irods::callback)>(exec_rule_expression));
    return re;

} // plugin_factory




