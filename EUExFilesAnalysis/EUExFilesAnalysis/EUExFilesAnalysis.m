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
    if ([absFilePath hasPrefix:@"exterbox://"]){
        NSLog(@"这是判断 ”exterbox://“ 的逻辑，因为引擎里没添加此逻辑，所以在此添加的");
        NSString *documentPath = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
        NSString *basicPath = [documentPath stringByAppendingPathComponent:@"exterbox"];
        if (![[NSFileManager defaultManager] fileExistsAtPath:basicPath]) {
            [[NSFileManager defaultManager] createDirectoryAtPath:basicPath withIntermediateDirectories:YES attributes:nil error:nil];
        }
        absFilePath = [basicPath stringByAppendingPathComponent:[absFilePath substringFromIndex:@"exterbox://".length]];
    }
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

//将16进制的字符串转换成NSData
- (NSMutableData *)convertHexStrToData:(NSString *)str {
    if (!str || [str length] == 0) {
        return nil;
    }
    
    NSMutableData *hexData = [[NSMutableData alloc] initWithCapacity:8];
    NSRange range;
    if ([str length] %2 == 0) {
        range = NSMakeRange(0,2);
    } else {
        range = NSMakeRange(0,1);
    }
    for (NSInteger i = range.location; i < [str length]; i += 2) {
        unsigned int anInt;
        NSString *hexCharStr = [str substringWithRange:range];
        NSScanner *scanner = [[NSScanner alloc] initWithString:hexCharStr];
        
        [scanner scanHexInt:&anInt];
        NSData *entity = [[NSData alloc] initWithBytes:&anInt length:1];
        [hexData appendData:entity];
        
        range.location += range.length;
        range.length = 2;
    }
    
    return hexData;
}

#pragma mark - Public Method
- (void)dismissViewController{
    NSLog(@"那算了");
}

@end
