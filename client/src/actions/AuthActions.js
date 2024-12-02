import * as AuthApi from "../api/AuthRequests";

export const logIn = (formData, navigate) => async (dispatch) => {
  dispatch({ type: "AUTH_START" });
  try {
    const { data } = await AuthApi.logIn(formData);
    dispatch({ type: "AUTH_SUCCESS", data: data });

    // Redirect to home page on successful login
    navigate("/home", { replace: true });
  } catch (error) {
    console.error("Login Error:", error?.response?.data || error.message);
    dispatch({ type: "AUTH_FAIL" });
  }
};

export const signUp = (formData, navigate) => async (dispatch) => {
  dispatch({ type: "AUTH_START" });
  try {
    const { data } = await AuthApi.signUp(formData);
    dispatch({ type: "AUTH_SUCCESS", data: data });

    // Redirect to home page on successful signup
    navigate("/home", { replace: true });
  } catch (error) {
    console.error("Signup Error:", error?.response?.data || error.message);
    dispatch({ type: "AUTH_FAIL" });
  }
};

export const logout = () => async (dispatch) => {
  dispatch({ type: "LOG_OUT" });
};
