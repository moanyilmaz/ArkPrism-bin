import { used } from './entry/oh_modules/sample/sdk';

export class EntryAbility {
  onCreate() {
    used();
  }
}
