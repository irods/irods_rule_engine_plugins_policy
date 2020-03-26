
#include "event_handler_utilities.hpp"

#include "irods_resource_backport.hpp"

#include "rcMisc.h"
#include "objDesc.hpp"

#include "boost/lexical_cast.hpp"

// Persistent L1 File Descriptor Table
extern l1desc_t L1desc[NUM_L1_DESC];

namespace irods {

    auto get_index_and_json_from_obj_inp(const dataObjInp_t* _inp) -> std::tuple<int, json>
    {
        int l1_idx{};
        dataObjInfo_t* obj_info{};
        for(const auto& l1 : L1desc) {
            if(FD_INUSE != l1.inuseFlag) {
                continue;
            }
            if(!strcmp(l1.dataObjInp->objPath, _inp->objPath)) {
                obj_info = l1.dataObjInfo;
                l1_idx = &l1 - L1desc;
            }
        }

        if(nullptr == obj_info) {
            THROW(
                SYS_INVALID_INPUT_PARAM,
                "no object found");
        }

        auto jobj = serialize_dataObjInp_to_json(*_inp);

        return std::make_tuple(l1_idx, jobj);

    } // get_index_and_resource_from_obj_inp

    auto serialize_keyValPair_to_json(const keyValPair_t& _kvp) -> json
    {
        json j;
        if(_kvp.len > 0) {
            for(int i = 0; i < _kvp.len; ++i) {
               if(_kvp.keyWord && _kvp.keyWord[i]) {
                    if(_kvp.value && _kvp.value[i]) {
                        j[_kvp.keyWord[i]] = _kvp.value[i];
                    }
                    else {
                        j[_kvp.keyWord[i]] = "empty_value";
                    }
                }
            }
        } else {
            j["keyValPair_t"] = "nullptr";
        }

        return j;

    } // serialize_keyValPair_to_json

    auto serialize_dataObjInp_to_json(const dataObjInp_t& _inp) -> json
    {
        json j;
        j["obj_path"]    = _inp.objPath;
        j["create_mode"] = boost::lexical_cast<std::string>(_inp.createMode);
        j["open_flags"]  = boost::lexical_cast<std::string>(_inp.openFlags);
        j["offset"]      = boost::lexical_cast<std::string>(_inp.offset);
        j["data_size"]   = boost::lexical_cast<std::string>(_inp.dataSize);
        j["num_threads"] = boost::lexical_cast<std::string>(_inp.numThreads);
        j["opr_type"]    = boost::lexical_cast<std::string>(_inp.oprType);
        j["cond_input"]  = serialize_keyValPair_to_json(_inp.condInput);

        return j;

    } // seralize_dataObjInp_to_json

    auto serialize_openedDataObjInp_to_json(const openedDataObjInp_t& _inp) -> json
    {
        json j;
        j["l1_desc_inx"]   = boost::lexical_cast<std::string>(_inp.l1descInx);
        j["len"]           = boost::lexical_cast<std::string>(_inp.len);
        j["whence"]        = boost::lexical_cast<std::string>(_inp.whence);
        j["opr_type"]      = boost::lexical_cast<std::string>(_inp.oprType);
        j["offset"]        = boost::lexical_cast<std::string>(_inp.offset);
        j["bytes_written"] = boost::lexical_cast<std::string>(_inp.bytesWritten);
        j["cond_input"]    = serialize_keyValPair_to_json(_inp.condInput);

        return j;

    } // seralize_openedDataObjInp_to_json

    auto serialize_rsComm_to_json(rsComm_t* _comm) -> json
    {
        json j;
        if (_comm) {
            j["client_addr"] = _comm->clientAddr;

            if(_comm->auth_scheme) {j["auth_scheme"] = _comm->auth_scheme;}

            j["proxy_user_name"] = _comm->proxyUser.userName;
            j["proxy_rods_zone"] = _comm->proxyUser.rodsZone;
            j["proxy_user_type"] = _comm->proxyUser.userType;
            j["proxy_sys_uid"] = boost::lexical_cast<std::string>(_comm->proxyUser.sysUid);
            j["proxy_auth_info_auth_scheme"] = _comm->proxyUser.authInfo.authScheme;
            j["proxy_auth_info_auth_flag"] = boost::lexical_cast<std::string>(_comm->proxyUser.authInfo.authFlag);
            j["proxy_auth_info_flag"] = boost::lexical_cast<std::string>(_comm->proxyUser.authInfo.flag);
            j["proxy_auth_info_ppid"] = boost::lexical_cast<std::string>(_comm->proxyUser.authInfo.ppid);
            j["proxy_auth_info_host"] = _comm->proxyUser.authInfo.host;
            j["proxy_auth_info_auth_str"] = _comm->proxyUser.authInfo.authStr;
            j["proxy_user_other_info_user_info"] = _comm->proxyUser.userOtherInfo.userInfo;
            j["proxy_user_other_info_user_comments"] = _comm->proxyUser.userOtherInfo.userComments;
            j["proxy_user_other_info_user_create"] = _comm->proxyUser.userOtherInfo.userCreate;
            j["proxy_user_other_info_user_modify"] = _comm->proxyUser.userOtherInfo.userModify;

            j["user_user_name"] = _comm->clientUser.userName;
            j["user_rods_zone"] = _comm->clientUser.rodsZone;
            j["user_user_type"] = _comm->clientUser.userType;
            j["user_sys_uid"] = boost::lexical_cast<std::string>(_comm->clientUser.sysUid);
            j["user_auth_info_auth_scheme"] = _comm->clientUser.authInfo.authScheme;
            j["user_auth_info_auth_flag"] = boost::lexical_cast<std::string>(_comm->clientUser.authInfo.authFlag);
            j["user_auth_info_flag"] = boost::lexical_cast<std::string>(_comm->clientUser.authInfo.flag);
            j["user_auth_info_ppid"] = boost::lexical_cast<std::string>(_comm->clientUser.authInfo.ppid);
            j["user_auth_info_host"] = _comm->clientUser.authInfo.host;
            j["user_auth_info_auth_str"] = _comm->clientUser.authInfo.authStr;
            j["user_user_other_info_user_info"] = _comm->clientUser.userOtherInfo.userInfo;
            j["user_user_other_info_user_comments"] = _comm->clientUser.userOtherInfo.userComments;
            j["user_user_other_info_user_create"] = _comm->clientUser.userOtherInfo.userCreate;
            j["user_user_other_info_user_modify"] = _comm->clientUser.userOtherInfo.userModify;
        } else {
            j["rsComm_ptr"] = "nullptr";
        }

        return j;

    } // serialize_rsComm_ptr

} // namespace irods

