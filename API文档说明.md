# uexFilesAnalysis

# 1、简介
证书解析
## 1.2、UI展示
无
## 1.3、 开源源码
无
# 2、API概览
## 2.1、 方法


> ### uexFilesAnalysis  证书文件解析接口
`uexFilesAnalysis.fileAnalysis(JSON.stringify(param));`


**参数:**

| 参数名称 |      参数类型 | 是否必须 | 说明 |
| ------ | ----- | ----- | ------|
| param | String | 是| 该字符串为JSON 格式，参见param列表|

**param列表参数:**

| 参数名称 |      参数类型 | 是否必须 | 说明 |
| ------ | ----- | ----- | ------|
|  filePath  |        String    |  是   |      文件路径     |
| password | String | 是| 解析文件的密码|

**平台支持:**

Android
iOS

**版本支持:**

4.1.0+

**示例:**


```
				function CheckRootTask() {
            				var json = {
            					filePath: "wgts://filedata.pfx",
            					password:"123456"
            				};
            				uexFilesAnalysis.fileAnalysis(JSON.stringify(json));
            	}

```


> ### uexFilesAnalysis 解析结果的回调
`uexFilesAnalysis.cbAnalysisData`


| 参数名称 |      参数类型 | 是否必须 | 说明 |
| ------ | ----- | ----- | ------|
| param | String | 是| 该字符串为JSON 格式，参见param列表|


**param列表参数:**

| 参数名称 |      参数类型 | 是否必须 | 说明 |
| ------ | ----- | ----- | ------|
| version | String | 是| ..|
| type | String | 是| ..|
| subjectDN | String | 是| ..|
| sigAlgName | String | 是| ..|
| notBefore | String | 是| ..|
| NotAfter | String | 是| ..|
| serialNumber | String | 是| ..|
| serialNumberLong | String | 是| ..|
| issuerDNName | String | 是| ..|
| publicKeyStr | String | 是| ..|
| status | String | 是| 成功是ok失败是fail|
| info | String | 是| 失败返回错误信息，成功没有|

**平台支持:**

Android
iOS


**版本支持:**

4.1.0+

**示例:**


```
				window.uexOnload = function(type) {

            				uexFilesAnalysis.cbAnalysisData = function(param) {


                            var json=JSON.parse(param);
                            console.info("json======="+json);
            				};

            			}
```



# 3、更新历史

API 版本： uexFilesAnalysis-4.0.3（iOS|Android）
 最近更新时间：2018-3-18

|  历史发布版本 | iOS更新  |Android|
| ------------ | ------------ | ------------ |----------|
| 4.1.0 | uexFilesAnalysis 新增插件 |uexFilesAnalysis 新增插件 |
