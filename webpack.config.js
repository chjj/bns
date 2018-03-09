'use strict';

const UglifyJsPlugin = require('uglifyjs-webpack-plugin');

module.exports = {
  target: 'web',
  entry: {
    'bns': './lib/bns'
  },
  output: {
    library: 'bns',
    libraryTarget: 'umd',
    path: __dirname,
    filename: '[name].js'
  },
  resolve: {
    modules: ['node_modules'],
    extensions: ['-browser.js', '.js', '.json']
  },
  module: {
    rules: [{
      test: /\.js$/,
      loader: 'babel-loader'
    }]
  },
  plugins: [
    new UglifyJsPlugin()
  ]
};
