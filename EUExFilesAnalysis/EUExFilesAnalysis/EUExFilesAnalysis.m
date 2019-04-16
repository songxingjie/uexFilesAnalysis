//
//  EUExFilesAnalysis.m
//  EUExFilesAnalysis
//
//  Created by 郭杰 on 2019/4/15.
//  Copyright © 2019 songxingjie. All rights reserved.
//

#import "EUExFilesAnalysis.h"
#import "PrAndPu.h"

@interface EUExFilesAnalysis()
@property (nonatomic,retain)ACJSFunctionRef *findBackUserCallbackFunc;

@end

@implementation EUExFilesAnalysis

#pragma mark - Life Cycle

- (instancetype)initWithWebViewEngine:(id<AppCanWebViewEngineObject>)engine{
    self = [super initWithWebViewEngine:engine];
    if (self) {
        ACLogDebug(@"插件实例被创建");
    }
    return self;
}

- (void)clean{
    [self dismissViewController];
    ACLogDebug(@"网页即将被销毁");
}

-(void)dealloc {
    [self clean];
}

#pragma mark - JavaScript API
- (void)fileAnalysis:(NSMutableArray *)inArguments{
    ACArgsUnpack(NSDictionary *info) = inArguments;
    NSString *filePath = stringArg(info[@"filePath"]);
    NSString *password = stringArg(info[@"password"]);
    NSString *absFilePath = [self absPath:filePath];
//    absFilePath = [[NSBundle mainBundle] pathForResource:@"APPCAN.pfx" ofType:nil];
//    password = @"111111";
    NSData *data = [NSData dataWithContentsOfFile:absFilePath];
    if (data) {
        PrAndPu *pp = [[PrAndPu alloc] init];
        [pp analyticalCertificateFromPKCS12File:absFilePath passphrase:password];
        [self.webViewEngine callbackWithFunctionKeyPath:@"uexFilesAnalysis.cbAnalysisData"
                                              arguments:ACArgsPack(pp.dicInfo.ac_JSONFragment)
                                             completion:^(JSValue * _Nullable returnValue) {
                                                 if (returnValue) {
                                                     //  ACLogDebug(@"回调成功!");
                                                     NSLog(@"回调成功!");
                                                 }else {
                                                     NSLog(@"回调失败");
                                                 }
                                             }];
    }else {
        NSMutableDictionary *dic = [NSMutableDictionary dictionary];
        [dic setValue:@"fail" forKey:@"status"];
        [dic setValue:@"无效的证书文件" forKey:@"info"];
        //ac_JSONFragment 方法，可以将NSDictionary转换成JSON字符串
        [self.webViewEngine callbackWithFunctionKeyPath:@"uexFilesAnalysis.cbAnalysisData"
                                              arguments:ACArgsPack(dic.ac_JSONFragment)
                                             completion:^(JSValue * _Nullable returnValue) {
                                                 if (returnValue) {
                                                     //  ACLogDebug(@"回调成功!");
                                                     NSLog(@"回调成功!");
                                                 }else {
                                                     NSLog(@"回调失败");
                                                 }
                                             }];
    }
}

#pragma mark - Public Method
- (void)dismissViewController{
    NSLog(@"那算了");
}

@end
