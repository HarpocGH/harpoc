import { configure } from "@testing-library/preact";
import { options } from "preact";

options.requestAnimationFrame = (callback) => {
  queueMicrotask(callback);
};
configure({ asyncUtilTimeout: 4000 });
