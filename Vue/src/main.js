import { createApp } from "vue";
import { createRouter, createWebHistory } from "vue-router";
import routes from "./router";
import App from "./App.vue";

const router = createRouter({
  history: createWebHistory(),
  routes,
});

var app = createApp(App);
app.use(router);
app.mount("#app");
