import type { Theme } from "vitepress";
import DefaultTheme from "vitepress/theme";
import HomeLayout from "./HomeLayout.vue";

import "./style.css";

export default {
  extends: DefaultTheme,
  Layout: HomeLayout,
} satisfies Theme;
