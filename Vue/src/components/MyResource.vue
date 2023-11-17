<template>
  <p>Get Resource form Server Side</p>
  <h1>{{ result }}</h1>
  <a href="http://localhost:8088/sso/login">login now</a>
</template>

<script>
export default {
  data() {
    return {
      result: "",
    };
  },
  mounted() {
    this.fetchData();
  },
  methods: {
    fetchData() {
      const headers = {};
      const token = localStorage.getItem('token');
      if(token)
      {
        headers.Authorization = token;
      }
      fetch("/home/resource", { headers })
        .then((response) => response.text())
        .then((data) => {
          this.result = data;
        })
        .catch((error) => {
          this.result = error;
        });
    },
  },
};
</script>

<style scoped>
h1 {
  margin: 20px 0;
}
</style>
