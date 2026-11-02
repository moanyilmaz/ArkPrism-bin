import { used } from './sdk';

export class EntryAbility {
  onCreate() {
    used();
  }
}
