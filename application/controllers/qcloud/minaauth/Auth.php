<?php

/**
 * Created by PhpStorm.
 * User: ayisun
 * Date: 2016/10/1
 * Time: 15:06
 */
class Auth
{

    public function __construct()
    {
        require_once('application/services/qcloud/minaauth/Cappinfo_Service.php');
        require_once('application/services/qcloud/minaauth/Csessioninfo_Service.php');
        require_once('system/wx_decrypt_data/old/decrypt_data.php');
        require_once('system/wx_decrypt_data/new/wxBizDataCrypt.php');
        require_once('system/return_code.php');
        require_once('system/report_data/ready_for_report_data.php');
        require_once('system/http_util.php');
        require_once('system/db/init_db.php');
    }

    /**
     * @param $code
     * @param $appid
     * @param $secret
     * @return array|int
     * 描述：登录校验，返回id和skey
     */
    public function get_id_skey($code, $encrypt_data,$iv="old")
    {
        $cappinfo_service = new Cappinfo_Service();
        $cappinfo_data = $cappinfo_service->select_cappinfo();
        if (empty($cappinfo_data) || ($cappinfo_data == false)) {
            $ret['returnCode'] = return_code::MA_NO_APPID;
            $ret['returnMessage'] = 'NO_APPID';
            $ret['returnData'] = '';
        } else {
            $appid = $cappinfo_data['appid'];
            $secret = $cappinfo_data['secret'];
            $ip = $cappinfo_data['ip'];
            $qcloud_appid = $cappinfo_data['qcloud_appid'];
            $login_duration = $cappinfo_data['login_duration'];
            $url = 'https://api.weixin.qq.com/sns/jscode2session?appid=' . $appid . '&secret=' . $secret . '&js_code=' . $code . '&grant_type=authorization_code';
            $http_util = new http_util();
            $return_message = $http_util->http_get($url);
            if ($return_message!=false) {
                $json_message = json_decode($return_message, true);
                if (isset($json_message['openid']) && isset($json_message['session_key']) ) {
                    $uuid = md5((time()-mt_rand(1, 10000)) . mt_rand(1, 1000000));//生成UUID
                    $skey = md5(time() . mt_rand(1, 1000000));//生成skey
                    $create_time = date('Y-m-d H:i:s',time());
                    $last_visit_time = date('Y-m-d H:i:s',time());
                    $openid = $json_message['openid'];
                    $session_key = $json_message['session_key'];
                    $errCode = 0;
                    $user_info = false;
                    //兼容旧的解密算法
                    if($iv == "old"){
                        $decrypt_data = new decrypt_data();
                        $user_info = $decrypt_data->aes128cbc_Decrypt($encrypt_data, $session_key);
                        log_message("INFO","userinfo:".$user_info);
                        $user_info = base64_encode($user_info);
                    }else{
                        $pc = new WXBizDataCrypt($appid, $session_key);
                        $errCode = $pc->decryptData($encrypt_data, $iv, $user_info);
                        $user_info = base64_encode($user_info);
                    }
                    if ($user_info === false || $errCode !== 0) {
                        $ret['returnCode'] = return_code::MA_DECRYPT_ERR;
                        $ret['returnMessage'] = 'DECRYPT_FAIL';
                        $ret['returnData'] = '';
                    } else {
                        $params = array(
                            "uuid" => $uuid,
                            "skey" => $skey,
                            "create_time" => $create_time,
                            "last_visit_time" => $last_visit_time,
                            "openid" => $openid,
                            "session_key" => $session_key,
                            "user_info" => $user_info,
                            "login_duration" => $login_duration
                        );

                        $csessioninfo_service = new Csessioninfo_Service();
                        $change_result = $csessioninfo_service->change_csessioninfo($params);
                        if ($change_result === true) {
                            $id = $csessioninfo_service->get_id_csessioninfo($openid);
                            $arr_result['id'] = $id;
                            $arr_result['skey'] = $skey;
                            $arr_result['user_info'] = json_decode(base64_decode($user_info));
                           
                            $ret['returnCode'] = return_code::MA_OK;
                            $ret['returnMessage'] = 'NEW_SESSION_SUCCESS';
                            $ret['returnData'] = $arr_result;
                        } else if ($change_result === false) {
                            $ret['returnCode'] = return_code::MA_CHANGE_SESSION_ERR;
                            $ret['returnMessage'] = 'CHANGE_SESSION_ERR';
                            $ret['returnData'] = '';
                        } else {
                            $arr_result['id'] = $change_result;
                            $arr_result['skey'] = $skey;
                            $arr_result['user_info'] = json_decode(base64_decode($user_info));
                           
                            $ret['returnCode'] = return_code::MA_OK;
                            $ret['returnMessage'] = 'UPDATE_SESSION_SUCCESS';
                            $ret['returnData'] = $arr_result;
                        }
                    }
                } else if (isset($json_message['errcode']) && isset($json_message['errmsg'])) {
                    $ret['returnCode'] = return_code::MA_WEIXIN_CODE_ERR;
                    $ret['returnMessage'] = 'WEIXIN_CODE_ERR';
                    $ret['returnData'] = '';
                } else {
                    $ret['returnCode'] = return_code::MA_WEIXIN_RETURN_ERR;
                    $ret['returnMessage'] = 'WEIXIN_RETURN_ERR';
                    $ret['returnData'] = '';
                }
            } else {
                $ret['returnCode'] = return_code::MA_WEIXIN_NET_ERR;
                $ret['returnMessage'] = 'WEIXIN_NET_ERR';
                $ret['returnData'] = '';
            }

            /**
             * 上报数据部分
             */
            $report_data = new ready_for_report_data();

            $arr_report_data = array(
                "ip"=>$ip,
                "appid"=>$qcloud_appid,
                "login_count"=>0,
                "login_sucess"=>0,
                "auth_count"=>0,
                "auth_sucess"=>0
            );

            if($report_data->check_data()){
                $report_data->ready_data("login_count");
            }else{
                $arr_report_data['login_count']=1;
                $report_data->write_report_data(json_encode($arr_report_data));
            }
            if($ret['returnCode']==0){
                if($report_data->check_data()){
                    $report_data->ready_data("login_sucess");
                }else{
                    $arr_report_data['login_count']=1;
                    $arr_report_data['login_sucess']=1;
                    $report_data->write_report_data(json_encode($arr_report_data));
                }
            }
        }
        return $ret;
    }

    /**
     * @param $id
     * @param $skey
     * @return bool
     * 描述：登录态验证
     */
    public function auth($id, $skey)
    {
        //根据Id和skey 在cSessionInfo中进行鉴权，返回鉴权失败和密钥过期
        $cappinfo_service = new Cappinfo_Service();
        $cappinfo_data = $cappinfo_service->select_cappinfo();
        if (empty($cappinfo_data) || ($cappinfo_data == false)) {
            $ret['returnCode'] = return_code::MA_NO_APPID;
            $ret['returnMessage'] = 'NO_APPID';
            $ret['returnData'] = '';
        } else {
            $login_duration = $cappinfo_data['login_duration'];
            $session_duration = $cappinfo_data['session_duration'];
            $ip = $cappinfo_data['ip'];
            $qcloud_appid = $cappinfo_data['qcloud_appid'];

            $params = array(
                "uuid" => $id,
                "skey" => $skey,
                "login_duration" => $login_duration,
                "session_duration" => $session_duration
            );

            $csessioninfo_service = new Csessioninfo_Service();
            $auth_result = $csessioninfo_service->check_session_for_auth($params);
            if ($auth_result!==false) {
                $arr_result['user_info'] = json_decode(base64_decode($auth_result));
                $ret['returnCode'] = return_code::MA_OK;
                $ret['returnMessage'] = 'AUTH_SUCCESS';
                $ret['returnData'] = $arr_result;
            } else {
                $ret['returnCode'] = return_code::MA_AUTH_ERR;
                $ret['returnMessage'] = 'AUTH_FAIL';
                $ret['returnData'] = '';
            }

            /**
             * 上报数据部分
             */
            $report_data = new ready_for_report_data();

            $arr_report_data = array(
                "ip"=>$ip,
                "appid"=>$qcloud_appid,
                "login_count"=>0,
                "login_sucess"=>0,
                "auth_count"=>0,
                "auth_sucess"=>0
            );

            if($report_data->check_data()){
                $report_data->ready_data("auth_count");
            }else{
                $arr_report_data['auth_count']=1;
                $report_data->write_report_data(json_encode($arr_report_data));
            }
            if($ret['returnCode']==0){
                if($report_data->check_data()){
                    $report_data->ready_data("auth_sucess");
                }else{
                    $arr_report_data['auth_count']=1;
                    $arr_report_data['auth_sucess']=1;
                    $report_data->write_report_data(json_encode($arr_report_data));
                }
            }

        }
        return $ret;
    }

    /**
     * @param $id
     * @param $skey
     * @param $encrypt_data
     * @return bool|string
     * 描述：解密数据
     */
    public function decrypt($id, $skey, $encrypt_data)
    {
        //1、根据id和skey获取session_key。
        //2、session_key获取成功则正常解密,可能解密失败。
        //3、获取不成功则解密失败。
        $csessioninfo_service = new Csessioninfo_Service();
        $params = array(
            "id" => $id,
            "skey" => $skey
        );
        $result = $csessioninfo_service->select_csessioninfo($params);
        if ($result !== false && count($result) != 0 && isset($result['session_key'])) {
            $session_key = $result['session_key'];
            $decrypt_data = new decrypt_data();
            $data = $decrypt_data->aes128cbc_Decrypt($encrypt_data, $session_key);
            if ($data !== false) {
                $ret['returnCode'] = return_code::MA_OK;
                $ret['returnMessage'] = 'DECRYPT_SUCCESS';
                $ret['returnData'] = $data;
            } else {
                $ret['returnCode'] = return_code::MA_DECRYPT_ERR;
                $ret['returnMessage'] = 'GET_SESSION_KEY_SUCCESS_BUT_DECRYPT_FAIL';
                $ret['returnData'] = '';
            }
        } else {
            $ret['returnCode'] = return_code::MA_DECRYPT_ERR;
            $ret['returnMessage'] = 'GET_SESSION_KEY_FAIL';
            $ret['returnData'] = '';
        }
        return $ret;
    }

    public function init_data($appid,$secret,$qcloud_appid,$ip,$cdb_ip,$cdb_port,$cdb_user_name,$cdb_pass_wd){
        $init_db = new init_db();
        $params_db = array(
            "cdb_ip"=>$cdb_ip,
            "cdb_port"=>$cdb_port,
            "cdb_user_name" => $cdb_user_name,
            "cdb_pass_wd" => $cdb_pass_wd
        );
        if($init_db->init_db_config($params_db)){
            if($init_db->init_db_table()){
                $cappinfo_service = new Cappinfo_Service();
                $cappinfo_data = $cappinfo_service->select_cappinfo();
                $params = array(
                    "appid"=>$appid,
                    "secret"=>$secret,
                    "qcloud_appid"=>$qcloud_appid,
                    "ip"=>$ip
                );

                if(empty($cappinfo_data)){
                    if($cappinfo_service->insert_cappinfo($params))
                    {
                        $ret['returnCode'] = return_code::MA_OK;
                        $ret['returnMessage'] = 'INIT_APPINFO_SUCCESS';
                        $ret['returnData'] = '';
                    }else{
                        $ret['returnCode'] = return_code::MA_INIT_APPINFO_ERR;
                        $ret['returnMessage'] = 'INIT_APPINFO_FAIL';
                        $ret['returnData'] = '';
                    }
                }else if($cappinfo_data != false){
                    $cappinfo_service->delete_cappinfo();
                    if($cappinfo_service->insert_cappinfo($params))
                    {
                        $ret['returnCode'] = return_code::MA_OK;
                        $ret['returnMessage'] = 'INIT_APPINFO_SUCCESS';
                        $ret['returnData'] = '';
                    }else{
                        $ret['returnCode'] = return_code::MA_INIT_APPINFO_ERR;
                        $ret['returnMessage'] = 'INIT_APPINFO_FAIL';
                        $ret['returnData'] = '';
                    }
                }else{
                    $ret['returnCode'] = return_code::MA_MYSQL_ERR;
                    $ret['returnMessage'] = 'MYSQL_ERR';
                    $ret['returnData'] = '';
                }
            }
            else{
                $ret['returnCode'] = return_code::MA_INIT_APPINFO_ERR;
                $ret['returnMessage'] = 'INIT_APPINFO_FAIL';
                $ret['returnData'] = '';
            }

        }else{
            $ret['returnCode'] = return_code::MA_INIT_APPINFO_ERR;
            $ret['returnMessage'] = 'INIT_APPINFO_FAIL';
            $ret['returnData'] = '';
        }
        return $ret;
    }

}
