import deviceInfo from '@ohos.deviceInfo';

export function used() {
  return deviceInfo.serial;
}

export function unused() {
  return deviceInfo.serial;
}
