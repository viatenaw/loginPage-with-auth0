import React from "react";
import { Route } from "react-router-dom";
import PropTypes from "prop-types";
import AuthContext from "./AuthContext";

const SecureRoute = ({ component: Component, auth, scopes, ...rest }) => {
  return (
    <AuthContext.Consumer>
      {auth => (
        <Route
          {...rest}
          render={props => {
            // 1. Redirect to login if not logged in
            if (!auth.isAuthenticated()) return auth.login();

            // 2. Dsiplay message if the user lacks required scopes
            if (scopes.length > 0 && !auth.userHasScopes(scopes)) {
              return (
                <h1>
                  Unathorized - you need the following scope(s) to view this
                  page: {scopes.join(",")}.
                </h1>
              );
            }

            // 3. Render the component
            return <Component auth={auth} {...props} />;
          }}
        />
      )}
    </AuthContext.Consumer>
  );
};

SecureRoute.propTypes = {
  component: PropTypes.func.isRequired,
  auth: PropTypes.object.isRequired,
  scopes: PropTypes.array
};

SecureRoute.defaultProps = {
  scopes: []
};

export default SecureRoute;
