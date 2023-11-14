# 1. Server 安装和启动
## 操作系统
KeyCloak本身没有环境限制，我们以Windows Server为例进行演示

## 下载Keyclock
官网：https://www.keycloak.org/  
下载不同的版本：https://github.com/keycloak/keycloak/releases  
此处我们下载：21.1.2

## 下载JDK
以21.1.2为例，需要JDK17才能运行

## 启动测试环境
其实按着这篇官方手册，就可以启动并配置基础的用户了  
https://www.keycloak.org/getting-started/getting-started-zip  

## 配置生成环境
客户端环境默认支持HTTP，而且数据库会默认生成到项目文件夹中  
![image](https://github.com/nimezul/KeyCloakSSOSolution/assets/8761991/7fee4ea4-178a-4c47-9024-b071198770f2)  

生成环境，我们会配置HTTPS证书和数据库，我们在这个文件中添加配置项  
![image](https://github.com/nimezul/KeyCloakSSOSolution/assets/8761991/cd13902a-abc3-42d5-acbc-191060702a29)  
先kc.bat build，然后kc.bat start

配置数据库的参数，看：https://www.keycloak.org/server/db  
配置HTTPS，看：https://www.keycloak.org/server/enabletls  

# 2. Server SAML client配置
## 新建Realm
![image](https://github.com/nimezul/KeyCloakSSOSolution/assets/8761991/46a79db8-cef4-4166-81fa-4e3931d712c6)
![image](https://github.com/nimezul/KeyCloakSSOSolution/assets/8761991/e81a3229-ee94-4b5d-ba86-85a2361750da)

## 新建Client
![image](https://github.com/nimezul/KeyCloakSSOSolution/assets/8761991/c55d1962-47a9-4517-b101-a5c9fb500040)
![image](https://github.com/nimezul/KeyCloakSSOSolution/assets/8761991/f88daada-e3ae-486e-8bfb-6d2c49424ec5)

## 配置Client
Client ID 必填，这自然不用说。  
Valid redirect URIs 相当于一个跳转白名单，支持通配符。比如SSO登录成功后我们要跳转回我们的APP，这个地址起码要加在这里，否则到时候就会出错说是url错误之类的。  
![image](https://github.com/nimezul/KeyCloakSSOSolution/assets/8761991/04d44fec-cfc1-4247-9300-b703740decbb)

继续向下翻，Master SAML Processing URL就是你APP的回调URL  
Force POST binding 打开表示， IdP回调的时候是通过HTTP POST方法，请求你的回调地址  
![image](https://github.com/nimezul/KeyCloakSSOSolution/assets/8761991/3e9b067f-7dd8-49c4-b2db-35a89d0b2555)

继续向下翻，该部分表示， IdP响应回去的SAMLRequest中的Assertion是有签名的，客户端可以验证签名  
![image](https://github.com/nimezul/KeyCloakSSOSolution/assets/8761991/7601ee5d-081e-440e-838c-cd1465cd4259)

以下配置表示，客户端在发送SAMLRequest的时候，会对请求参数进行签名，服务端会验证签名的
![image](https://github.com/nimezul/KeyCloakSSOSolution/assets/8761991/7480eaee-4d00-44d6-a6e8-28be7642a1bf)

# 3. Client 原理
![image](https://github.com/nimezul/KeyCloakSSOSolution/assets/8761991/0770cbda-1268-43fd-a032-7ffbee994f38)
双发要通信，我们得知道一些信息，比如客户端发请求发到哪里？服务端响应到哪里？  
客户端和服务端在验证签名的时候，需要对方的公钥    
服务端肯定知道客户端的信息，因为上面我们配置了Client。  
那服务端也得给客户端它的信息，比如IdP URL 和 公钥证书。这个在这里找：  
![image](https://github.com/nimezul/KeyCloakSSOSolution/assets/8761991/b26b15a5-a403-4829-baa2-53a4742497ed)
点击之后其实是一个XML，我们从中可以找到刚才提到的信息  
![image](https://github.com/nimezul/KeyCloakSSOSolution/assets/8761991/7401512a-a83c-460f-b125-f4f51aef86c9)

# 4. SAML 协议原理
既然是基于SAML协议，那多少需要了解一下SAML。  

上面看到SAMLRequest 和 SAMLResponse，这些格式是什么？   
是XML经过base64之后的字符串。

XML格式是怎么样的，什么样的键值？  
一个典型的SAMLRequest XML
```
<samlp:AuthnRequestxmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"ID="identifier_1"Version="2.0"IssueInstant="2004-12-05T09:21:59Z"AssertionConsumerServiceIndex="1">
  <saml:Issuer>https://sp.example.com/SAML2</saml:Issuer>
  <samlp:NameIDPolicyAllowCreate="true"Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient"/>
</samlp:AuthnRequest>
```
一个典型的SAMLResponse XML
```
<samlp:Responsexmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"ID="identifier_2"InResponseTo="identifier_1"Version="2.0"IssueInstant="2004-12-05T09:22:05Z"Destination="https://sp.example.com/SAML2/SSO/POST">
  <saml:Issuer>https://idp.example.org/SAML2</saml:Issuer>
  <samlp:Status>
      <samlp:StatusCodeValue="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertionxmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"ID="identifier_3"Version="2.0"IssueInstant="2004-12-05T09:22:05Z">
    <saml:Issuer>https://idp.example.org/SAML2</saml:Issuer><!-- a POSTed assertion MUST be signed -->
    <ds:Signaturexmlns:ds="http://www.w3.org/2000/09/xmldsig#">...
    </ds:Signature>
    <saml:Subject>
        <saml:NameIDFormat="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">3f7b3dcf-1674-4ecd-92c8-1544f346baf8
        </saml:NameID>
        <saml:SubjectConfirmationMethod="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationDataInResponseTo="identifier_1"Recipient="https://sp.example.com/SAML2/SSO/POST"NotOnOrAfter="2004-12-05T09:27:05Z"/>
        </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:ConditionsNotBefore="2004-12-05T09:17:05Z"NotOnOrAfter="2004-12-05T09:27:05Z">
    <saml:AudienceRestriction>
        <saml:Audience>https://sp.example.com/SAML2</saml:Audience>
    </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatementAuthnInstant="2004-12-05T09:22:00Z"SessionIndex="identifier_3">
    <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
    </saml:AuthnContext>
    </saml:AuthnStatement>
  </saml:Assertion>
</samlp:Response>
```
这些只是皮毛，建议详细阅读协议文档： http://docs.oasis-open.org/security/saml/v2.0/  
这样的话你就知道，XML的属性有什么作用，什么时候使用，如何使用

比如，你发送SAMLRequest的时候，URL中的参数名是什么？你接收SAMLResponse响应的时候，参数名又是什么？  
还比如，如果客户端和服务端双方都签名了，签名在哪里？在XML中还是在URL中？对应的属性名字和URL参数名字又是什么？

# 5. Client 实现
见 Client 源代码
