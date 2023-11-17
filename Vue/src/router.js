import HelloWorld from "./components/HelloWorld.vue";
import MyResource from "./components/MyResource.vue";

const routers = [
  {
    path: "/resource",
    name: "resource",
    component: MyResource,
  },
  {
    path: "/",
    component: HelloWorld,
  },
];

export default routers;