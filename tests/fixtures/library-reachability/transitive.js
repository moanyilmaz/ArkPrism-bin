import { forward } from './forward';

export class EntryAbility {
  onCreate() {
    forward();
  }
}
