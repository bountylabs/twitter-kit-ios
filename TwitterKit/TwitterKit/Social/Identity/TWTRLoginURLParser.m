/*
 * Copyright (C) 2017 Twitter, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#import "TWTRLoginURLParser.h"
#import <SafariServices/SafariServices.h>
#import <TwitterCore/TWTRAuthConfig.h>
#import <TwitterCore/TWTRAuthenticationConstants.h>
#import <TwitterCore/TWTRNetworkingUtil.h>
#import "TWTRTwitter.h"
#import "TWTRWebAuthenticationFlow.h"
#import "TWTRWebAuthenticationViewController.h"

@interface TWTRLoginURLParser ()

@property (nonatomic, copy) NSString *twitterKitURLScheme;
@property (nonatomic, copy) NSString *twitterAuthURL;

@end

@implementation TWTRLoginURLParser

- (instancetype)initWithAuthConfig:(TWTRAuthConfig *)config
{
    if (self = [super init]) {
        self.twitterKitURLScheme = [NSString stringWithFormat:@"twitterkit-%@", config.consumerKey];
        _nonce = [[self generateNonce] copy];
        self.twitterAuthURL = [self.class authURLStringWithConsumerKey:config.consumerKey consumerSecret:config.consumerSecret twitterKitURLScheme:self.twitterKitURLScheme nonce:self.nonce];
    }
    return self;
}

+ (NSString *)authURLStringWithConsumerKey:(NSString *)consumerKey consumerSecret:(NSString *)consumerSecret twitterKitURLScheme:(NSString *)twitterKitURLScheme nonce:(NSString *)nonce
{
    NSMutableDictionary *parameters = [[NSMutableDictionary alloc] init];
    parameters[@"consumer_key"] = consumerKey;
    parameters[@"consumer_secret"] = consumerSecret;
    parameters[@"oauth_callback"] = twitterKitURLScheme;
    if (nonce.length > 0) {
        parameters[@"identifier"] = nonce;
    }

    NSString *queryString = [TWTRNetworkingUtil queryStringFromParameters:parameters];
    return [NSString stringWithFormat:@"twitterauth://authorize?%@", queryString];
}

#pragma mark - Public

- (NSString *)authRedirectScheme
{
    if ([self hasValidURLScheme]) {
        return self.twitterKitURLScheme;
    } else {
        return TWTRSDKScheme;
    }
}

- (BOOL)isMobileSSOSuccessURL:(NSURL *)url
{
    BOOL properScheme = [self isTwitterKitRedirectURL:url];

    NSDictionary *parameters = [TWTRNetworkingUtil parametersFromQueryString:url.host];
    NSArray *keys = [parameters allKeys];
    BOOL successState = [keys containsObject:@"secret"] && [keys containsObject:@"token"] && [keys containsObject:@"username"] && [keys containsObject:@"identifier"] && properScheme;

    BOOL isSuccessURL = successState && properScheme;

    return isSuccessURL;
}

- (BOOL)isMobileSSOCancelURL:(NSURL *)url
{
    BOOL properScheme = [self isTwitterKitRedirectURL:url];
    BOOL cancelState = (url.host == nil) && properScheme;

    BOOL isCancelURL = properScheme && cancelState;

    return isCancelURL;
}

- (BOOL)isOauthTokenVerifiedFromURL:(NSURL *)url
{
    NSDictionary *parameters = [TWTRNetworkingUtil parametersFromQueryString:url.absoluteString];
    NSString *token = parameters[TWTRAuthOAuthTokenKey];

    return [[[TWTRTwitter sharedInstance] sessionStore] isValidOauthToken:token];
}

- (BOOL)isIdentifierVerifiedFromURL:(NSURL *)url
{
    // Ignore this check if a nonce was not sent.
    if ([self.nonce length] <= 0) {
        return YES;
    }

    NSDictionary *parameters = [self parametersForSSOURL:url];
    NSString *identifier = parameters[@"identifier"];
    if (identifier == nil) {
        return NO;
    }

    return [self.nonce isEqualToString:identifier];
}

- (NSDictionary *)parametersForSSOURL:(NSURL *)url
{
    return [TWTRNetworkingUtil parametersFromQueryString:url.host];
}

- (BOOL)isTwitterKitRedirectURL:(NSURL *)url
{
    return [self isTwitterKitURLScheme:url.scheme];
}

- (BOOL)hasValidURLScheme
{
    return ([self appSpecificURLScheme] != nil);
}

- (NSURL *)twitterAuthorizeURL
{
    return [NSURL URLWithString:self.twitterAuthURL];
}

#pragma mark - Internal

- (BOOL)isTwitterKitURLScheme:(NSString *)scheme
{
    // The Twitter API will redirect to a lowercase version of the
    // URL that we pass to them
    return [scheme caseInsensitiveCompare:self.twitterKitURLScheme] == NSOrderedSame;
}

// This method parses the schemes from the Info.plist which has a
// format like this:
// @[ @{
//     @"CFBundleTypeRole": @"Editor",
//     @"CFBundleURLSchemes": @[@"twitterkit-k8Uf0x"],
//   },
//   @{
//     @"CFBundleTypeRole": @"Editor",
//     @"CFBundleURLSchemes": @[@"appscheme83289239"],
//   }
// ]
- (NSString *)appSpecificURLScheme
{
    NSString *matchingScheme;
    NSDictionary *infoPlist = [NSBundle mainBundle].infoDictionary;
    NSArray *urlTypes = [infoPlist objectForKey:@"CFBundleURLTypes"];

    for (NSDictionary *schemeDetails in urlTypes) {
        NSPredicate *predicate = [NSPredicate predicateWithBlock:^BOOL(id _Nullable evaluatedObject, NSDictionary<NSString *, id> *_Nullable bindings) {
            NSString *scheme = (NSString *)evaluatedObject;
            return (scheme) ? [self isTwitterKitURLScheme:scheme] : NO;
        }];

        NSArray *filteredArray = [[schemeDetails objectForKey:@"CFBundleURLSchemes"] filteredArrayUsingPredicate:predicate];
        if ([filteredArray count] > 0) {
            matchingScheme = [filteredArray firstObject];
        }
    }

    return matchingScheme;
}

- (NSString *)generateNonce
{
    NSMutableData *data = [NSMutableData dataWithLength:48];
    int result = SecRandomCopyBytes(NULL, 48, data.mutableBytes);
    if (result != 0) {
        return nil;
    }

    NSString *base64EncodedData = [data base64EncodedStringWithOptions:0];
    return base64EncodedData;
}

@end
