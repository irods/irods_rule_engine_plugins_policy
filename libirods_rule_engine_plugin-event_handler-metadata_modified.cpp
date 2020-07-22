
#include "irods_re_plugin.hpp"
#include "irods_re_ruleexistshelper.hpp"
#include "irods_plugin_context.hpp"
#include "irods_hierarchy_parser.hpp"
#include "policy_engine_utilities.hpp"
#include "event_handler_utilities.hpp"
#include "rule_engine_plugin_configuration_json.hpp"

#include "rcMisc.h"
#include "rsModAVUMetadata.hpp"

#include <boost/any.hpp>

#include "boost/lexical_cast.hpp"

#include <typeinfo>
#include <algorithm>

#include "json.hpp"

namespace fs = irods::experimental::filesystem;

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
                                    "pep_api_mod_avu_metadata_post",
                                    "pep_api_mod_avu_metadata_except",
                                    "pep_api_mod_avu_metadata_finally"};

    auto rule_name_is_supported(const std::string& _rule_name) {
        return (consumed_policy_enforcement_points.find(_rule_name) !=
                consumed_policy_enforcement_points.end());
    } // rule_name_is_supported

    namespace entity_type {
        inline const std::string data_object{"data_object"};
        inline const std::string collection{"collection"};
        inline const std::string resource{"resource"};
        inline const std::string user{"user"};
        inline const std::string unsupported{"unsupported"};
    } // entity_type

    auto get_entity_type(const std::string& _arg) {
        if("-d" == _arg) {
            return entity_type::data_object;
        }
        else if("-C" == _arg) {
            return entity_type::collection;
        }
        else if("-R" == _arg) {
            return entity_type::resource;
        }
        else if("-u" == _arg) {
            return entity_type::user;
        }
        else {
            return entity_type::unsupported;
        }
    }

    void event_metadata_modified(
        const std::string&           _rule_name,
        ruleExecInfo_t*              _rei,
        const std::list<boost::any>& _arguments) {

        auto comm_obj = irods::serialize_rsComm_to_json(_rei->rsComm);

        if("pep_api_mod_avu_metadata_pre"     == _rule_name ||
           "pep_api_mod_avu_metadata_post"    == _rule_name ||
           "pep_api_mod_avu_metadata_except"  == _rule_name ||
           "pep_api_mod_avu_metadata_finally" == _rule_name) {
            auto it = _arguments.begin();
            std::advance(it, 2);
            if(_arguments.end() == it) {
                THROW(
                    SYS_INVALID_INPUT_PARAM,
                    "invalid number of arguments");
            }

            const auto meta_inp{boost::any_cast<modAVUMetadataInp_t*>(*it)};
            const auto event{peps_to_events.at(_rule_name)};
            const auto entity_type = get_entity_type(meta_inp->arg1);

            json jobj{};
            jobj["event"] = event;
            if(entity_type::data_object == entity_type ||
               entity_type::collection  == entity_type) {
                jobj["logical_path"] = meta_inp->arg2;
            }
            else if(entity_type::resource == entity_type) {
                jobj["source_resource"] = meta_inp->arg2;
            }
            else if(entity_type::user == entity_type) {
                jobj["user_name"] = meta_inp->arg2;
            }

            jobj["metadata"] = {
                {"comm",        comm_obj},
                {"operation",   meta_inp->arg0},
                {"entity_type", entity_type},
                {"attribute",   meta_inp->arg3},
                {"value",       meta_inp->arg4},
                {"units",       meta_inp->arg5}
            };

            jobj["policy_enforcement_point"] = _rule_name;

            auto policies_to_invoke = config->plugin_configuration.at("policies_to_invoke");

            irods::invoke_policies_for_object(_rei, event, _rule_name, policies_to_invoke, jobj);
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
#if 0
    // build a list of pep strings for the regexp
    std::string regex{};
    for( auto& s : consumed_policy_enforcement_points) {
        regex += s + " || ";
    }

    // trim trailing " || "
    regex = regex.substr(0, regex.size()-4);

    // register the event handler's peps as implemented by this plugin
    RuleExistsHelper::Instance()->registerRuleRegex(regex);
#endif
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
    catch(const boost::bad_lexical_cast& _e) {
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
    catch(const std::exception& _e) {
        irods::exception_to_rerror(
            SYS_NOT_SUPPORTED,
            _e.what(),
            rei->rsComm->rError);
        return ERROR(
                   SYS_NOT_SUPPORTED,
                   _e.what());
    }
    catch(const json::exception& _e) {
        irods::exception_to_rerror(
            SYS_NOT_SUPPORTED,
            _e.what(),
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




