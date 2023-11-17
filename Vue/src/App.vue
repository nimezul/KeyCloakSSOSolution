<template>
  <div class="menu">
    <router-link to="/">Home</router-link>
    <router-link to="/resource">Private resources</router-link>
  </div>

  <router-view></router-view>
</template>

<script>
export default {
  name: "App",
  mounted() {
    const cookies = document.cookie;
    const token = this.getCookieValue(cookies, "token");
    if (token) {
      localStorage.setItem("token", token);
    }
  },
  methods: {
    getCookieValue(cookies, name) {
      const cookieArr = cookies.split(";");
      for (let i = 0; i < cookieArr.length; i++) {
        const cookie = cookieArr[i].trim();
        if (cookie.startsWith(`${name}=`)) {
          return cookie.substring(name.length + 1);
        }
      }
      return null;
    },
  },
};
</script>

<style>
* {
  padding: 0;
  margin: 0;
}
#app {
  color: #2c3e50;
  text-align: center;
}
.menu {
  height: 60px;
  line-height: 60px;
  background: #2c3e50;
  margin-bottom: 50px;
}
.menu a {
  margin: 0 10px;
  color: #fff;
  text-decoration: none;
}
.menu a:hover {
  text-decoration: underline;
}
</style>
