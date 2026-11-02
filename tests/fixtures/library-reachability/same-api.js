import deviceInfo from '@ohos.deviceInfo';

export class EntryAbility {
  onCreate() {
    return deviceInfo.serial;
  }
}
