# 写日志信息
function Log-Message([string]$Msg,[switch]$PassThru) 
{
  #"[{0}] $Msg" -f (Get-Date -Format "yyyy-dd-MM HH:mm:ss.fffff") | Add-Content $logFile -Force -ea SilentlyContinue
  
  $strDate = "[{0}] " -f (Get-Date -Format "yyyy-dd-MM HH:mm:ss.fffff")
  [string]::Concat($strDate,$Msg) | Add-Content $logFile -Force -ea SilentlyContinue
  if ($PassThru) {
    Write-Output $Msg
  }
}

# 1.检查防火墙设置
function Check-Firewall()
{
    Log-Message "开始检查防火墙状态......" -PassThru
    
    # 防火墙设置命令在Windows Server 2012和Windows 8之前有所不同，新操作系统使用Set-NetFirewallProfile命令，老版本使用netsh命令
    $osVersion = Get-WmiObject -Class Win32_OperatingSystem -ComputerName . | Select-Object -Property Caption,Version

    Log-Message "信息：当前的操作系统版本号：$($osVersion.Version)"
    Log-Message "信息：当前的操作系统版本名：$($osVersion.Caption)"

    $idx = $osVersion.Version.LastIndexOf(".")
    $osVersionValue = [Double]($osVersion.Version.Substring(0,$idx))

    # 判断是否是server系统
    if($osVersion.Caption.Contains("Windows Server")){
        Log-Message "信息：关闭windows Server操作系统上的防火墙" -PassThru
        if($osVersionValue -lt 6.3){ 
            netsh advfirewall set allprofiles state off
        }else{
            Set-NetFirewallProfile -Enabled False
        }
    }else{  # 非Server系统
        Log-Message "信息：关闭非windows Server操作系统上的防火墙" -PassThru
        if($osVersionValue -lt 8.0){
            netsh advfirewall set allprofiles state off
        }else{
            Set-NetFirewallProfile -Enabled False
        }
    }

    Log-Message "防火墙状态设置完成......" -PassThru
}

# 2.检查NET Framework 4.5是否安装
function Check-NETFramework45()
{
    Log-Message "开始检查NET Framework版本......" -PassThru

    # 检查操作系统中是否安装了.NET Framework 4.5
    $netVersion = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Client' -Name Version

    $netIdx = $netVersion.Version.LastIndexOf(".")
    $netVersionValue = [Double]($netVersion.Version.Substring(0,$netIdx))

    Log-Message "信息：当前NET Framework版本：$($netVersion.Version)" -PassThru

    # 版本号不等于4.5时需要新安装
    if($netVersionValue -ne 4.5){
    #Install-WindowsFeature NET-Framework-Core –Source D:\Sources\sxs
        Log-Message "信息：开始安装NET Framework 4.5......."
        Start-Process -FilePath $dotFrameworkPath -ArgumentList "/q /norestart" -Wait -NoNewWindow

        #Sleep -Seconds 10

        Log-Message "信息：NET Framework 4.5安装完成......."
    }

    Log-Message "NET Framework版本检查完成......" -PassThru
}

# 3.安装并授权ArcGIS Server
function Install-AGSServer()
{
    # 1.安装ArcGIS Server
    Log-Message "开始安装ArcGIS Server......" -PassThru
    Log-Message "信息：ArcGIS Server安装路径：$INSTALLDIR" -PassThru
    Log-Message "信息：ArcGIS Server安装账号：$USER_NAME / $PASSWORD" -PassThru
    
    $serverParams = "/qb INSTALLDIR=$INSTALLDIR INSTALLDIR1=$INSTALLDIR1 USER_NAME=$USER_NAME PASSWORD=$PASSWORD"
    Start-Process -FilePath $agsServerPath -ArgumentList $serverParams -Wait -NoNewWindow

    Log-Message "ArcGIS Server安装完成......" -PassThru

    # 2.授权ArcGIS Server
    Log-Message "开始授权ArcGIS Server......" -PassThru
    
    $authEXEPath=Join-Path $env:CommonProgramFiles "ArcGIS\bin\SoftwareAuthorization.exe"
    $authParams="/s /Ver 10.4 /LIF " + $agsServerKey
    Start-Process -FilePath $authEXEPath -ArgumentList $authParams -Wait -NoNewWindow

    Log-Message "ArcGIS Server授权完成......" -PassThru

    # 3.重启ArcGIS Server服务
    Log-Message "开始重启ArcGIS Server服务......" -PassThru

    $agsServiceName="ArcGIS Server"
    $agsServiceStatus = (Get-Service $agsServiceName).Status

    Log-Message "信息：当前ArcGIS Server服务启动状态：$agsServiceStatus"

    if($agsServiceStatus -eq "Running"){
        Restart-Service -Name $agsServiceName
    }else{
        Start-Service -Name $agsServiceName
    }

    Log-Message "信息：系统休眠60秒，等待ArcGIS Server系统服务启动完成"

    Start-Sleep -Seconds 60

    Log-Message "ArcGIS Server服务重启完成......" -PassThru
}

# 4.1.使用https访问时，忽略所有证书安全问题
function Ignore-SelfSignedCerts
{
    Log-Message "信息：使用https访问时，设置忽略所有证书安全警告"

<#
    Add-Type -TypeDefinition  @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy
    {
        public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem)
        {
            return true;
        }
    }
"@

    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
#>

    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $True }

    Log-Message "信息：忽略所有证书安全警告设置完成"
}

# 4.2.调用Admin API创建站点
function Create-AGSSite()
{
    Log-Message "开始创建ArcGIS Server站点......" -PassThru

    Log-Message "信息：设置站点参数信息"
    Log-Message "信息：ArcGIS Server站点的配置存储路径：$agsConfigStorePath" -PassThru
    Log-Message "信息：ArcGIS Server站点的服务目录路径：$agsServiceDirPath" -PassThru

    # 10.5之前使用下面的localRepositoryPath参数
    $localRepositoryPath=$agsServiceDirPath + "\\local"
    # 10.5中的localRepositoryPath定义在这里
    $configStoreConnection = @"
    {
        "type":"FILESYSTEM",
        "connectionString": "$agsConfigStorePath",
        "localRepositoryPath": "$localRepositoryPath"   
    }
"@

    $directories=@"
    {
        "directories": [
			  {
			    "name": "arcgiscache",
			    "physicalPath": "$agsServiceDirPath\\directories\\arcgiscache",
			    "directoryType": "CACHE",
			    "cleanupMode": "NONE",
			    "maxFileAge": 0,
			    "description": "Stores tile caches used by map, globe, and image services for rapid performance."
			  },
			  {
			    "name": "arcgisjobs",
			    "physicalPath": "$agsServiceDirPath\\directories\\arcgisjobs",
			    "directoryType": "JOBS",
			    "cleanupMode": "TIME_ELAPSED_SINCE_LAST_MODIFIED",
			    "maxFileAge": 360,
			    "description": "Stores results and other information from geoprocessing services."
			  },
			  {
			    "name": "arcgisoutput",
			    "physicalPath": "$agsServiceDirPath\\directories\\arcgisoutput",
			    "directoryType": "OUTPUT",
			    "cleanupMode": "TIME_ELAPSED_SINCE_LAST_MODIFIED",
			    "maxFileAge": 10,
			    "description": "Stores various information generated by services, such as map images."
			  },
			  {
			    "name": "arcgissystem",
			    "physicalPath": "$agsServiceDirPath\\arcgissystem",
			    "directoryType": "SYSTEM",
			    "cleanupMode": "NONE",
			    "maxFileAge": 0,
			    "description": "Stores directories and files used internally by ArcGIS Server."
			  }			 
		]
    }
"@

    $logsSettings=@"
    {
  		"logLevel": "INFO",
  		"logDir": "$agsServiceDirPath\\logs\\",
  		"maxErrorReportsCount": 10,
  		"maxLogFileAge": 90
	}
"@

    Log-Message "信息：站点参数设置完成" -PassThru
    Log-Message "信息：参数configStoreConnection：$configStoreConnection" 
    Log-Message "信息：参数directories：$directories" 
    Log-Message "信息：参数logsSettings：$logsSettings" 

    # 使用https访问时，忽略所有证书安全警告
    Ignore-SelfSignedCerts

    $adminURL = "https://"+$env:COMPUTERNAME+":6443/arcgis/admin/createNewSite"

    Log-Message "信息：站点Admin网站访问网址：$adminURL" -PassThru
    Log-Message "信息：开始发送创建站点请求"  -PassThru

<#    # 方法1：使用Net对象发送Web请求
    # 构造HTTP请求
    $http_request = New-Object -ComObject Msxml2.XMLHTTP
    $http_request.open('POST', $adminURL, $false)
    $http_request.setRequestHeader("Content-type", "application/x-www-form-urlencoded")

    $params = "username=$SITEADMIN&password=$SITEPWD&configStoreConnection=$configStoreConnection&directories=$directories&logsSettings=$logsSettings&runAsync=false&f=json"
    $http_request.send($params)

    Log-Message "信息：创建站点请求执行完成。"  -PassThru
    Log-Message "信息：创建站点请求执行完成返回信息：status:$($http_request.status),content:$($http_request.responseText)"

    $responseJson = ConvertFrom-StringData $http_request.responseText
    # END方法1
#>

    # 方法2：使用内建方法发送Web请求
    $body = @{
        username=$SITEADMIN;
        password=$SITEPWD;
        configStoreConnection=$configStoreConnection;
        directories=$directories;
        logsSettings=$logsSettings;
        runAsync="false";
        f="json"
    }

    $responseJson=Invoke-RestMethod -Uri $adminURL -Method Post -Body $body
    
    Log-Message "信息：创建站点请求执行完成。"  -PassThru
    # END方法2

    if($responseJson.status -eq "success"){
        Log-Message "信息：站点创建完成。" -PassThru

        Start-Sleep -Seconds 60

        return 1
    }
    
    # messages是Object[]数组类型，转单行字符串
    $responseMsgs=$responseJson.messages | ForEach-Object {$_.toString()}
    $responseShortMsgs=[string]::Join("",$responseMsgs)
    Log-Message "错误：站点创建失败。错误信息：$responseShortMsgs" -PassThru
    Log-Message "错误：站点创建执行返回信息：status=$($responseJson.status),messages=$responseShortMsgs,code=$($responseJson.code)"

    return 0  
}

# 将多行文本转换为单行文本信息
function ConvertTo-ShortString([string]$longTxt)
{
    # 按换行符分割，必须用双引号，单引号则当原始字符用
    $txtArray = $longTxt.Split("`n")
    return [string]::Join("`t",$txtArray)
}

#########################################################################
## 启动脚本
#########################################################################
try{
    # 脚本所用参数列表
    $agsSoftwarePath=Split-Path -Parent $MyInvocation.MyCommand.Path
    $logFile= Join-Path $agsSoftwarePath "agsserver-install.log"
    $dotFrameworkPath=Join-Path $agsSoftwarePath  "dotnet\NDP452-KB2901907-x86-x64-AllOS-ENU.exe"
    $agsServerPath= Join-Path $agsSoftwarePath "ArcGISServer1041\Setup.exe"
    $agsServerKey= Join-Path $agsSoftwarePath "server.ecp"
    
    #AGS SERVER安装参数列表，需要自定义设置
    $INSTALLDIR="C:\arcgis"
    $INSTALLDIR1=$INSTALLDIR

    $USER_NAME="arcgis"
    $PASSWORD="ArcGIS1041"

    #AGS SERVER站点创建参数列表
    $SITEADMIN="siteadmin"
    $SITEPWD="esri"
    $agsConfigStorePath="C:\\arcgisserver\\config-store"
    $agsServiceDirPath="C:\\arcgisserver"

    # 第一步：检查防火墙状态
    #Check-Firewall

    # 第二步：检查NET Framework 4.5是否安装
    #Check-NETFramework45

    # 第三步：安装并授权ArcGIS Server
    #Install-AGSServer

    # 第四步：创建site站点
    Create-AGSSite
}
catch
{
    Log-Message "错误：$($_.Exception.Message)" -PassThru
}

