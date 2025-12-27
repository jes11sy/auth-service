import { UAParser } from 'ua-parser-js';

export interface ParsedUserAgent {
  device: string;
  deviceType: 'mobile' | 'tablet' | 'desktop';
  os: string;
  browser: string;
}

/**
 * Парсит User-Agent строку и возвращает структурированную информацию
 * @param userAgent Raw User-Agent string
 * @returns Parsed device information
 */
export function parseUserAgent(userAgent: string): ParsedUserAgent {
  const parser = new UAParser(userAgent);
  const result = parser.getResult();

  const osName = result.os.name || 'Unknown OS';
  const osVersion = result.os.version || '';
  const browserName = result.browser.name || 'Unknown Browser';
  const browserVersion = result.browser.version ? result.browser.version.split('.')[0] : '';

  // Формируем красивую строку устройства
  const device = `${osName}${osVersion ? ' ' + osVersion : ''} - ${browserName}${browserVersion ? ' ' + browserVersion : ''}`;

  // Определяем тип устройства
  let deviceType: 'mobile' | 'tablet' | 'desktop' = 'desktop';
  if (result.device.type === 'mobile') {
    deviceType = 'mobile';
  } else if (result.device.type === 'tablet') {
    deviceType = 'tablet';
  }

  return {
    device,
    deviceType,
    os: osName,
    browser: browserName,
  };
}

/**
 * Упрощенная версия для отображения только типа устройства
 */
export function getDeviceType(userAgent: string): 'mobile' | 'tablet' | 'desktop' {
  return parseUserAgent(userAgent).deviceType;
}

