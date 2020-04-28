
#include "irods_re_plugin.hpp"
#include "irods_exception.hpp"

#include "filesystem.hpp"
#include "rodsError.h"

#include "json.hpp"

namespace irods {
    using json = nlohmann::json;

    auto get_index_and_json_from_obj_inp(const dataObjInp_t*) -> std::tuple<int, json>;
    auto serialize_keyValPair_to_json(const keyValPair_t&) -> json;
    auto serialize_dataObjInp_to_json(const dataObjInp_t&) -> json;
    auto serialize_openedDataObjInp_to_json(const openedDataObjInp_t& _inp) -> json;
    auto serialize_rsComm_to_json(rsComm_t*) -> json;
    void invoke_policies_for_object(
            ruleExecInfo_t*, const std::string&, const std::string&, const json&, const json&);

    auto evaluate_metadata_conditional(const json&, const json&) -> bool;
} // namespace irods
