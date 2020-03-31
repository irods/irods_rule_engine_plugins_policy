
#include "irods_re_plugin.hpp"
#include "irods_re_ruleexistshelper.hpp"
#include "irods_plugin_context.hpp"
#include "irods_hierarchy_parser.hpp"
#include "event_handler_utilities.hpp"
#include "rule_engine_plugin_configuration_json.hpp"

#include "rcMisc.h"
#include "rsModAVUMetadata.hpp"

#include <boost/any.hpp>

#include "boost/lexical_cast.hpp"

#include "policy_engine_utilities.hpp"

#include <typeinfo>
#include <algorithm>

#include "json.hpp"
using json = nlohmann::json;

namespace {
    const std::map<std::string, std::string> peps_to_events{
        { "pep_api_mod_avu_metadata_pre",  "METADATA" },
        { "pep_api_mod_avu_metadata_post", "METADATA" }
    };

    std::unique_ptr<irods::plugin_configuration_json> config;
    std::string plugin_instance_name{};
    std::set<std::string> consumed_policy_enforcement_points{
                                    "pep_api_mod_avu_metadata_pre",
                                    "pep_api_mod_avu_metadata_post"};

    auto rule_name_is_supported(const std::string& _rule_name) {
        return (consumed_policy_enforcement_points.find(_rule_name) !=
                consumed_policy_enforcement_points.end());
    } // rule_name_is_supported

    void invoke_policies_for_object(
        ruleExecInfo_t*    _rei,
        const std::string& _event,
        const std::string& _rule_name,
        const std::string& _obj_json_str) {
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
            auto policy_clauses = policy["active_policy_clauses"];
            if(policy_clauses.empty()) {
                continue;
            }

            for(auto& p : policy_clauses) {
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

                        auto cfg{policy["configuration"]};
                        std::string pn{policy["policy"]};

                        std::string params = _obj_json_str;
                        std::string config = cfg.dump();

                        args.clear();
                        args.push_back(boost::any(std::ref(params)));
                        args.push_back(boost::any(std::ref(config)));

                        irods::invoke_policy(_rei, pn, args);
                    } // for ops

                } // if suffix
            } // for pre_post
        } // for policy
    } // invoke_policies_for_object

    auto get_entity_type(const std::string& _arg) {
        if("-d" == _arg) {
            return "data_object";
        }
        else if("-C" == _arg) {
            return "collection";
        }
        else if("-R" == _arg) {
            return "resource";
        }
        else if("-u" == _arg) {
            return "user";
        }
        else {
            return "unsupported";
        }
    }

    void event_metadata_modified(
        const std::string&           _rule_name,
        ruleExecInfo_t*              _rei,
        const std::list<boost::any>& _arguments) {
        try {
            auto comm_obj = irods::serialize_rsComm_to_json(_rei->rsComm);

            if("pep_api_mod_avu_metadata_pre"  == _rule_name ||
               "pep_api_mod_avu_metadata_post" == _rule_name) {
                auto it = _arguments.begin();
                std::advance(it, 2);
                if(_arguments.end() == it) {
                    THROW(
                        SYS_INVALID_INPUT_PARAM,
                        "invalid number of arguments");
                }

                auto meta_inp = boost::any_cast<modAVUMetadataInp_t*>(*it);

                auto event = peps_to_events.at(_rule_name);

                json jobj{};
                jobj["event"]       = event;
                jobj["operation"]   = meta_inp->arg0;
                jobj["entity_type"] = get_entity_type(meta_inp->arg1);
                jobj["target"]      = meta_inp->arg2;
                jobj["attribute"]   = meta_inp->arg3;
                jobj["value"]       = meta_inp->arg4;
                jobj["unit"]        = meta_inp->arg5;
                jobj["policy_enforcement_point"] = _rule_name;

                invoke_policies_for_object(_rei, event, _rule_name, jobj.dump());
            }
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

    } // event_metadata_modified

} // namespace

irods::error start(
    irods::default_re_ctx&,
    const std::string& _instance_name ) {

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
        event_metadata_modified(_rule_name, rei, _arguments);
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




