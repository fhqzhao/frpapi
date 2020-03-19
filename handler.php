<?php 

//error_reporting(0);
Header("Content-type: text/plain");
$conn = mysqli_connect("rm-8vbf1w78735wl9ip258870.mysql.zhangbei.rds.aliyuncs.com", "fhqzhao", "lamp@1986", "sfrp") or die("Database error");


function save_logs($file,$msg) {
    $myfile = fopen($file, "a") or die("Unable to open file! ".$file);
    fwrite($myfile, $msg);
    fwrite($myfile, "<br/>".PHP_EOL);
    fclose($myfile);
}

// 输出禁止错误 Header
function ServerForbidden($msg) {
	Header("HTTP/1.1 403 {$msg}");
	echo json_encode(Array(
		'status' => 403,
		'message' => $msg
	), JSON_UNESCAPED_UNICODE);
	exit;
}

// 输出未找到错误 Header
function ServerNotFound($msg) {
	Header("HTTP/1.1 404 {$msg}");
	echo json_encode(Array(
		'status' => 404,
		'message' => $msg
	), JSON_UNESCAPED_UNICODE);
	exit;
}

// 输出未找到错误 Header
function ServerBadRequest($msg) {
	Header("HTTP/1.1 400 {$msg}");
	echo json_encode(Array(
		'status' => 400,
		'message' => $msg
	), JSON_UNESCAPED_UNICODE);
	exit;
}

// 输出正常消息
function LoginSuccessful($msg) {
	Header("Content-type: text/plain", true, 200);
	echo json_encode(Array(
		'status' => 200,
		'success' => true,
		'message' => $msg
	), JSON_UNESCAPED_UNICODE);
	exit;
}

// 输出正常消息
function CheckSuccessful($msg) {
	Header("Content-type: text/plain", true, 200);
	echo json_encode(Array(
		'status' => 200,
		'success' => true,
		'message' => $msg
	), JSON_UNESCAPED_UNICODE);
	exit;
}


// Json 格式消息输出
function Println($data) {
	Header("Content-type: text/plain", true, 200);
	echo json_encode($data, JSON_UNESCAPED_UNICODE);
	exit;
}

function getBoolean($str) {
	return $str == "true";
}

//RejectInvalidUser
//拒绝授予--fhqzhao
function RejectGrant($msg) {
	Header("Content-type: text/plain", true, 200);
	echo json_encode(Array(
		'status' => 200,
		'reject' => true,
		'reject_reason' => $msg
	), JSON_UNESCAPED_UNICODE);
	exit;
}


//允许且内容不需要变动--fhqzhao
function SuccessUnChange($msg) {
	Header("Content-type: text/plain", true, 200);
	echo json_encode(Array(
		'status' => 200,
		'reject' => false,
		'unchange' => true,
		'reject_reason' => $msg
	), JSON_UNESCAPED_UNICODE);
	exit;
}

//允许且需要替换操作内容--fhqzhao
function SuccessChangeContent($arr) {
	Header("Content-type: text/plain", true, 200);
	echo json_encode(Array(
		'status' => 200,
		'reject' => false,
		'unchange' => true,
		'content' => $arr,
		'reject_reason' => $msg
	), JSON_UNESCAPED_UNICODE);
	exit;
}



if(!isset($_SERVER['HTTP_X_FRP_REQID'])){
    save_logs("log.txt","非法请求！");
    ServerForbidden("非法请求！");
}

$URI =$_SERVER['REQUEST_URI'];
$REQID =$_SERVER['HTTP_X_FRP_REQID'];
save_logs("info.html",$REQID);
$OBJ=file_get_contents("php://input"); 
save_logs("info.html",$OBJ);
save_logs("info.html","<hr/>");

$data = json_decode($OBJ, TRUE);   //格式化
save_logs("log.txt",$data["op"]);


if(!isset($data["op"])){
    save_logs("log.txt","op action error！");
    ServerNotFound("Invalid request");   
    exit();
}

switch($data["op"]) {
    case "Login":
	    if(!isset($data["content"]["user"])) {
	        save_logs("log.txt","Username cannot be empty！");
	        RejectGrant("Username cannot be empty");    //用户名不能为空
	    }
	    if(!preg_match("/^[A-Za-z0-9]{1,32}$/", $data["content"]["user"])){
	         RejectGrant("Invalid username");            //用户名不合法
	    }
	    $userToken = mysqli_real_escape_string($conn, $data["content"]["user"]);
		$rs = mysqli_fetch_array(mysqli_query($conn, "SELECT * FROM `tokens` WHERE `username`='{$userToken}'"));
        if($rs) {
            save_logs("log.txt","Login successful,username:".$data["content"]["user"]);
	        SuccessUnChange("Login successful, welcome!");    //登录成功
		} else {
		     RejectGrant("Login failed,invalid user");                //登录失败，用户名无效
		}
        break;
    case "NewProxy":
        if(!preg_match("/^[A-Za-z0-9]{1,32}$/", $data["content"]["user"]["user"])){
	         RejectGrant("Invalid username");            //用户名不合法
	    }
        $username     = $data["content"]["user"]["user"];
        $proxyName    = $data["content"]["proxy_name"];
		$proxyType    = $data["content"]["proxy_type"] ?? "tcp";
		$remotePort   = Intval($data["content"]["remote_port"]) ?? "";
		$username    = mysqli_real_escape_string($conn, $username);
		$rs           = mysqli_fetch_array(mysqli_query($conn, "SELECT * FROM `tokens` WHERE `username`='{$username}'"));
        if(!$rs){
             RejectGrant("Create New proxy failed failed,invalid user");   //建立连接失败，用户名无效果（令牌无效）
        } 
        if($proxyType == "tcp" || $proxyType == "udp" || $proxyType == "stcp" || $proxyType == "xtcp") {
            $sql="SELECT id,username,proxy_name,proxy_type,remote_port,status FROM `proxies` WHERE `username`='{$username}' AND `remote_port`='{$remotePort}' AND `proxy_type`='{$proxyType}'";
            save_logs("log.txt",$sql);
            $rs = mysqli_fetch_array(mysqli_query($conn, $sql));
            if($rs){
            	if($rs['status'] == "1") {
					RejectGrant("Proxy banned"); //已被禁使用
				}
				save_logs("log.txt",$proxyName."--------------------start success!");
				SuccessUnChange($proxyName.",  start success!"); //验证成功，启动代理
            }else{
                SuccessUnChange("not found Registration record !"); //没有找到代理记录
            }
            
        }elseif ($proxyType == "http" || $proxyType == "https") {
           
           	// 目前只验证域名和子域名
           	$domain    = $data["content"]["custom_domains"] ?? "null";
           	$subdomain    = $data["content"]["subdomain"] ?? "null";
			$domain    = mysqli_real_escape_string($conn, $domain);
			$subdomain = mysqli_real_escape_string($conn, $subdomain);
			
			$domainsql = (isset($domain ) && !empty($domain )) ? "`domain`='{$domain}'" : "`subdomain`='{$subdomain}'";
			$sql       = "SELECT id,username,proxy_name,proxy_type,remote_port,status FROM `proxies` WHERE `username`='{$username}' AND {$domainsql} AND `proxy_type`='{$proxyType}'";
			save_logs("log.txt",$sql);
			$rs        = mysqli_fetch_array(mysqli_query($conn, $sql ));
           
           if($rs){
            	if($rs['status'] == "1") {
					RejectGrant("Proxy banned"); //已被禁使用
				}
				save_logs("log.txt",$proxyName."--------------------start success!");
				SuccessUnChange($proxyName.",  start success!"); //验证成功，启动代理
            }else{
                SuccessUnChange("not found Registration record !"); //没有找到代理记录
            }
           
        }else {
			RejectGrant("Invalid request，".$proxyType); //无效的请求类型
		}

        break;
    default:
		ServerNotFound("Undefined action of op");
}

?>
