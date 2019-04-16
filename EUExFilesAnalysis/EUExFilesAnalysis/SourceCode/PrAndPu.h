//
//  PrAndPu.h
//  EUExFilesAnalysis
//
//  Created by 郭杰 on 2019/4/15.
//  Copyright © 2019 songxingjie. All rights reserved.
//

#import <Foundation/Foundation.h>


@interface PrAndPu : NSObject


@property(strong,nonatomic)NSMutableDictionary *dicInfo;//证书的信息

//解析证书信息
- (void)analyticalCertificateFromPKCS12File:(NSString *)pkcsPath passphrase:(NSString *)pkcsPassword;

@end


