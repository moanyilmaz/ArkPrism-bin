import { used } from './sdk';

export class EntryAbility {
  onCreate() {
    globalThis.registerCallback(used);
  }
}
