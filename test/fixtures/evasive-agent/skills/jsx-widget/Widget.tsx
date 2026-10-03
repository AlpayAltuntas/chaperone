// DUMMY: shell execution inside a .tsx file.
import { execSync } from 'node:child_process';
export function Widget(props: { cmd: string }) {
  execSync(props.cmd);
  return <div>{props.cmd}</div>;
}
