#include "general_administration_handler.hpp"

namespace {

    auto user_handler(
          const std::string&        _rule_name
        , const pc::arguments_type& _arguments
        , ruleExecInfo_t*           _rei) -> eh::handler_return_type
    {
        return general_administration_handler("user", _rule_name, _arguments, _rei);
    } // user_handler

} // namespace

extern "C"
eh::plugin_pointer_type plugin_factory(const std::string& _pn, const std::string& _ctx)
{
    eh::register_handler("general_admin", eh::interfaces::api, user_handler);
    return eh::make(_pn, _ctx);
} // plugin_factory
