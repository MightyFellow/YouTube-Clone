import React from "react";
import styled from "styled-components";
import Youtube from "../img/logo.png";
import {
  Home,
  ExploreOutlined,
  SubscriptionsOutlined,
  VideoLibraryOutlined,
  HistoryOutlined,
  LibraryMusicOutlined,
  SportsEsportsOutlined,
  SportsBasketballOutlined,
  MovieOutlined,
  ArticleOutlined,
  LiveTvOutlined,
  AccountCircleOutlined,
  SettingsOutlined,
  FlagOutlined,
  HelpOutlineOutlined,
  SettingsBrightnessOutlined,
} from "@mui/icons-material";
import { Link } from "react-router-dom";

const Container = styled.div`
  flex: 1;
  background-color: ${({ theme }) => theme.bgLighter};
  height: 100vh;
  color: ${({ theme }) => theme.text};
  font-size: 14px;
  position: sticky;
  top: 0;
  overflow-y: scroll;
`;

const Wrapper = styled.div`
  padding: 18px 26px;
`;
const Logo = styled.div`
  display: flex;
  align-items: center;
  gap: 5px;
  font-weight: bold;
  margin-bottom: 25px;
`;

const Img = styled.img`
  height: 25px;
`;

const Item = styled.div`
  display: flex;
  align-items: center;
  gap: 20px;
  cursor: pointer;
  padding: 7.5px 0;
  &:hover {
    background-color: ${({ theme }) => theme.soft};
  }
`;

const Hr = styled.hr`
  margin: 15px 0px;
  border: 0.5px solid ${({ theme }) => theme.soft};
`;

const Login = styled.div``;
const Button = styled.button`
  padding: 5px 15px;
  background-color: transparent;
  border: 1px solid #3ea6ff;
  color: #3ea6ff;
  border-radius: 3px;
  font-weight: 500;
  margin-top: 10px;
  cursor: pointer;
  display: flex;
  align-items: center;
  gap: 5px;
`;

const Title = styled.h2`
  font-size: 14px;
  font-weight: 500;
  color: #aaaaaa;
  margin-bottom: 20px;
`;

const Menu = ({ darkMode, setDarkMode }) => {
  return (
    <Container>
      <Wrapper>
        <Link to="/" style={{ textDecoration: "none", color: "inherit" }}>
          <Logo>
            <Img src={Youtube} />
            Youtube
          </Logo>
          <Item>
            <Home />
            Home
          </Item>
          <Item>
            <ExploreOutlined />
            Explore
          </Item>
          <Item>
            <SubscriptionsOutlined />
            Subscriptions
          </Item>
          <Hr />
          <Item>
            <VideoLibraryOutlined />
            Library
          </Item>
          <Item>
            <HistoryOutlined />
            History
          </Item>
          <Hr />
          <Login>
            Sign in to like videos, comment, and subscribe.
            {/* <Link to="signin" style={{ textDecoration: "none" }}>
            
          </Link> */}
            <Link to="signin" style={{ textDecoration: "none" }}>
              <Button>
                <AccountCircleOutlined />
                SIGN IN
              </Button>
            </Link>
          </Login>
          <Hr />
          <Title>BEST OF YOUTUBE</Title>
          <Item>
            <LibraryMusicOutlined />
            Music
          </Item>
          <Item>
            <SportsBasketballOutlined />
            Sports
          </Item>
          <Item>
            <SportsEsportsOutlined />
            Gaming
          </Item>
          <Item>
            <MovieOutlined />
            Movies
          </Item>
          <Item>
            <ArticleOutlined />
            News
          </Item>
          <Item>
            <LiveTvOutlined />
            Live
          </Item>
          <Hr />
          <Item>
            <SettingsOutlined />
            Settings
          </Item>
          <Item>
            <FlagOutlined />
            Report
          </Item>
          <Item>
            <HelpOutlineOutlined />
            Help
          </Item>
          <Item onClick={() => setDarkMode(!darkMode)}>
            <SettingsBrightnessOutlined />
            {darkMode ? "Light" : "Dark"} Mode
          </Item>
        </Link>
      </Wrapper>
    </Container>
  );
};

export default Menu;
