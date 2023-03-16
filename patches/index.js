import { ConnectorConfigFormItemType, ConnectorType, validateConfig, ConnectorError, ConnectorErrorCodes, parseJson } from '@logto/connector-kit';
import { got, HTTPError } from 'got';
import { createHmac } from 'crypto';
import { z } from 'zod';

// https://github.com/facebook/jest/issues/7547
const assert = (value, error) => {
    if (!value) {
        // https://github.com/typescript-eslint/typescript-eslint/issues/3814
        // eslint-disable-next-line @typescript-eslint/no-throw-literal
        throw error;
    }
};

const endpoint = 'https://dysmsapi.aliyuncs.com/';
const staticConfigs = {
    Format: 'json',
    RegionId: 'cn-hangzhou',
    SignatureMethod: 'HMAC-SHA1',
    SignatureVersion: '1.0',
    Version: '2017-05-25',
};
/**
 * Details of SmsTemplateType can be found at:
 * https://next.api.aliyun.com/document/Dysmsapi/2017-05-25/QuerySmsTemplateList.
 *
 * In our use case, it is to send verification code SMS for passwordless sign-in/up as well as
 * reset password. The default value of type code is set to 2.
 */
var SmsTemplateType;
(function (SmsTemplateType) {
    SmsTemplateType[SmsTemplateType["Notification"] = 0] = "Notification";
    SmsTemplateType[SmsTemplateType["Promotion"] = 1] = "Promotion";
    SmsTemplateType[SmsTemplateType["VerificationCode"] = 2] = "VerificationCode";
    SmsTemplateType[SmsTemplateType["InternationalMessage"] = 6] = "InternationalMessage";
    SmsTemplateType[SmsTemplateType["PureNumber"] = 7] = "PureNumber";
})(SmsTemplateType || (SmsTemplateType = {}));
const defaultMetadata = {
    id: 'aliyun-short-message-service',
    target: 'aliyun-sms',
    platform: null,
    name: {
        en: 'Aliyun Short Message Service',
        'zh-CN': '阿里云短信服务',
        'tr-TR': 'Aliyun SMS Servisi',
        ko: 'Aliyun Short 메세지 서비스',
    },
    logo: './logo.svg',
    logoDark: null,
    description: {
        en: 'Aliyun provides cloud computing services to online businesses.',
        'zh-CN': '阿里云是全球性的云服务提供商。',
        'tr-TR': 'Aliyun, çevrimiçi işletmelere bulut bilişim hizmetleri sunmaktadır.',
        ko: 'Aliyun는 온라인 비지니스를 위해 클라우딩 컴퓨팅 서비스를 제공합니다.',
    },
    readme: './README.md',
    formItems: [
        {
            key: 'accessKeyId',
            label: 'Access Key ID',
            type: ConnectorConfigFormItemType.Text,
            required: true,
            placeholder: '<access-key-id>',
        },
        {
            key: 'accessKeySecret',
            label: 'Access Key Secret',
            type: ConnectorConfigFormItemType.Text,
            required: true,
            placeholder: '<access-key-secret>',
        },
        {
            key: 'signName',
            label: 'Signature Name',
            type: ConnectorConfigFormItemType.Text,
            required: true,
            placeholder: '<signature-name>',
        },
        {
            key: 'templates',
            label: 'Templates',
            type: ConnectorConfigFormItemType.Json,
            required: true,
            defaultValue: [
                {
                    usageType: 'SignIn',
                    templateCode: '<template-code>',
                    intlTemplateCode: '<template-code>',
                },
                {
                    usageType: 'Register',
                    templateCode: '<template-code>',
                    intlTemplateCode: '<template-code>',
                },
                {
                    usageType: 'ForgotPassword',
                    templateCode: '<template-code>',
                    intlTemplateCode: '<template-code>',
                },
                {
                    usageType: 'Generic',
                    templateCode: '<template-code>',
                    intlTemplateCode: '<template-code>',
                },
                {
                    usageType: 'Test',
                    templateCode: '<template-code>',
                    intlTemplateCode: '<template-code>',
                },
            ],
        },
    ],
};

// Aliyun has special escape rules.
// https://help.aliyun.com/document_detail/29442.html
const escaper = (string_) => encodeURIComponent(string_)
    .replace(/\*/g, '%2A')
    .replace(/'/g, '%27')
    .replace(/!/g, '%21')
    .replace(/"/g, '%22')
    .replace(/\(/g, '%28')
    .replace(/\)/g, '%29')
    .replace(/\+/g, '%2B');
const getSignature = (parameters, secret, method) => {
    const canonicalizedQuery = Object.keys(parameters)
        .map((key) => {
        const value = parameters[key];
        return value === undefined ? '' : `${escaper(key)}=${escaper(value)}`;
    })
        .filter(Boolean)
        .slice()
        .sort()
        .join('&');
    const stringToSign = `${method.toUpperCase()}&${escaper('/')}&${escaper(canonicalizedQuery)}`;
    return createHmac('sha1', `${secret}&`).update(stringToSign).digest('base64');
};
const request = async (url, parameters, accessKeySecret) => {
    const finalParameters = {
        ...parameters,
        SignatureNonce: String(Math.random()),
        Timestamp: new Date().toISOString(),
    };
    const signature = getSignature(finalParameters, accessKeySecret, 'POST');
    return got.post({
        url,
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        form: { ...finalParameters, Signature: signature },
    });
};

/**
 * @doc https://help.aliyun.com/document_detail/101414.html
 */
const sendSms = async (parameters, accessKeySecret) => {
    return request(endpoint, { Action: 'SendSms', ...staticConfigs, ...parameters }, accessKeySecret);
};

const sendSmsResponseGuard = z.object({
    BizId: z.string().optional(),
    Code: z.string(),
    Message: z.string(),
    RequestId: z.string(),
});
/**
 * UsageType here is used to specify the use case of the template, can be either
 * 'Register', 'SignIn', 'ForgotPassword', 'Generic' or 'Test'.
 *
 * Type here in the template is used to specify the purpose of sending the SMS,
 * can be either item in SmsTemplateType.
 * As the SMS is applied for sending verification code, the value should always be 2 in our case.
 */
const requiredTemplateUsageTypes = ['Register', 'SignIn', 'ForgotPassword'];
const templateGuard = z.object({
    type: z.nativeEnum(SmsTemplateType).default(2),
    usageType: z.string(),
    templateCode: z.string(),
    intlTemplateCode: z.string(),
});
const aliyunSmsConfigGuard = z.object({
    accessKeyId: z.string(),
    accessKeySecret: z.string(),
    signName: z.string(),
    templates: z.array(templateGuard).refine((templates) => requiredTemplateUsageTypes.every((requiredType) => templates.map((template) => template.usageType).includes(requiredType)), (templates) => ({
        message: `Template with UsageType (${requiredTemplateUsageTypes
            .filter((requiredType) => !templates.map((template) => template.usageType).includes(requiredType))
            .join(', ')}) should be provided!`,
    })),
});

const sendMessage = (getConfig) => async (data, inputConfig) => {
    const { to, type, payload } = data;
    const config = inputConfig ?? (await getConfig(defaultMetadata.id));
    validateConfig(config, aliyunSmsConfigGuard);
    const { accessKeyId, accessKeySecret, signName, templates } = config;
    const template = templates.find(({ usageType }) => usageType === type);
    assert(template, new ConnectorError(ConnectorErrorCodes.TemplateNotFound, `Cannot find template!`));
    try {
        const httpResponse = await sendSms({
            AccessKeyId: accessKeyId,
            PhoneNumbers: to,
            SignName: signName,
            TemplateCode: to.startsWith('86') ? template.templateCode : template.intlTemplateCode,
            TemplateParam: JSON.stringify(payload),
        }, accessKeySecret);
        const { body: rawBody } = httpResponse;
        const { Code, Message, ...rest } = parseResponseString(rawBody);
        if (Code !== 'OK') {
            throw new ConnectorError(ConnectorErrorCodes.General, {
                errorDescription: Message,
                Code,
                ...rest,
            });
        }
        return httpResponse;
    }
    catch (error) {
        if (!(error instanceof HTTPError)) {
            throw error;
        }
        const { response: { body: rawBody }, } = error;
        assert(typeof rawBody === 'string', new ConnectorError(ConnectorErrorCodes.InvalidResponse));
        const { Code, Message, ...rest } = parseResponseString(rawBody);
        throw new ConnectorError(ConnectorErrorCodes.General, {
            errorDescription: Message,
            Code,
            ...rest,
        });
    }
};
const parseResponseString = (response) => {
    const result = sendSmsResponseGuard.safeParse(parseJson(response));
    if (!result.success) {
        throw new ConnectorError(ConnectorErrorCodes.InvalidResponse, result.error);
    }
    return result.data;
};
const createAliyunSmsConnector = async ({ getConfig }) => {
    return {
        metadata: defaultMetadata,
        type: ConnectorType.Sms,
        configGuard: aliyunSmsConfigGuard,
        sendMessage: sendMessage(getConfig),
    };
};

export { createAliyunSmsConnector as default };
