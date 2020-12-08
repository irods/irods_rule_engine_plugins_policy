#ifndef IRODS_GENERAL_ADMINISTRATION_HANDLER_HPP
#define IRODS_GENERAL_ADMINISTRATION_HANDLER_HPP

#include "policy_composition_framework_event_handler.hpp"

namespace {
    // clang-format off
    using     json = nlohmann::json;
    namespace ie   = irods::event_handler;
    namespace ipc  = irods::policy_composition;
    // clang-format on

    const ipc::event_map_type p2e{
        {"add",    "CREATE"},
        {"modify", "MODIFY"},
        {"rm",     "REMOVE"}
    };

    const ipc::event_map_type a2k{
        {"user",     "user_name"},
        {"resource", "source_resource"},
        {"zone",     "zone"}
    };

    auto general_administration_handler(
          const std::string&         _target
        , const std::string&         _rule_name
        , const ipc::arguments_type& _arguments
        , ruleExecInfo_t*            _rei) -> ie::handler_return_type
    {
        auto it = ipc::advance_or_throw(_arguments, 2);

        const auto inp{boost::any_cast<generalAdminInp_t*>(*it)};
        auto obj = ipc::serialize_generalAdminInp_to_json(*inp);

        if(_target != obj["target"]) {
            return std::make_tuple(ie::SKIP_POLICY_INVOCATION, json{});
        }

        obj[a2k.at(inp->arg1)] = inp->arg2;

        const auto event{p2e.at(inp->arg0)};

        obj["policy_enforcement_point"] = _rule_name;
        obj["event"] = event;
        obj["comm"]  = ipc::serialize_rsComm_to_json(_rei->rsComm);

        return std::make_tuple(event, obj);

    } // general_administration_handler

} // namespace


#endif // IRODS_GENERAL_ADMINISTRATION_HANDLER_HPP
