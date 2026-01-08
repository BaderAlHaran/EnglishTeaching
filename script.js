// ===== INTERSECTION OBSERVER FOR SCROLL ANIMATIONS =====
class ScrollAnimations {
  constructor() {
    this.init();
  }

  init() {
    this.setupIntersectionObserver();
    this.setupScrollEffects();
  }

  setupIntersectionObserver() {
    const observerOptions = {
      threshold: 0.1,
      rootMargin: '0px 0px -50px 0px'
    };

    this.observer = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          entry.target.classList.add('visible');
        }
      });
    }, observerOptions);

    // Observe all elements with fade-in class
    const animatedElements = document.querySelectorAll('.fade-in');
    animatedElements.forEach(el => this.observer.observe(el));
  }

  setupScrollEffects() {
    // Add fade-in class to elements that should animate
    const elementsToAnimate = [
      '.hero__content',
      '.hero__visual',
      '.section__header',
      '.feature__card',
      '.service__card',
      '.review__form',
      '.review__card',
      '.process__step',
      '.cta__content'
    ];

    elementsToAnimate.forEach(selector => {
      const elements = document.querySelectorAll(selector);
      elements.forEach((el, index) => {
        // Start with visible state
        el.style.opacity = '1';
        el.style.transform = 'translateY(0)';
        el.classList.add('fade-in');
        el.classList.add(`stagger-${(index % 4) + 1}`);
      });
    });
  }
}

// ===== ANIMATED COUNTER =====
class AnimatedCounter {
  constructor() {
    this.init();
  }

  init() {
    this.setupCounterObserver();
  }

  setupCounterObserver() {
    const counterObserver = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          this.animateCounter(entry.target);
          counterObserver.unobserve(entry.target);
        }
      });
    }, { threshold: 0.5 });

    const counters = document.querySelectorAll('.stat__number');
    counters.forEach(counter => counterObserver.observe(counter));
  }

  animateCounter(element) {
    const target = parseInt(element.getAttribute('data-target'));
    const duration = 2000; // 2 seconds
    const increment = target / (duration / 16); // 60fps
    let current = 0;

    const timer = setInterval(() => {
      current += increment;
      if (current >= target) {
        current = target;
        clearInterval(timer);
      }
      element.textContent = Math.floor(current).toLocaleString();
    }, 16);
  }
}

// ===== MOBILE NAVIGATION =====
class MobileNavigation {
  constructor() {
    this.navToggle = document.getElementById('nav-toggle');
    this.navMenu = document.getElementById('nav-menu');
    this.navLinks = document.querySelectorAll('.nav__link');
    
    this.init();
  }

  init() {
    this.navToggle.addEventListener('click', () => this.toggleMenu());
    
    // Close menu when clicking on nav links
    this.navLinks.forEach(link => {
      link.addEventListener('click', () => this.closeMenu());
    });

    // Close menu when clicking outside
    document.addEventListener('click', (e) => {
      if (!this.navMenu.contains(e.target) && !this.navToggle.contains(e.target)) {
        this.closeMenu();
      }
    });
  }

  toggleMenu() {
    this.navMenu.classList.toggle('active');
    this.navToggle.classList.toggle('active');
    
    // Toggle hamburger icon
    const icon = this.navToggle.querySelector('i');
    if (this.navMenu.classList.contains('active')) {
      icon.classList.remove('fa-bars');
      icon.classList.add('fa-times');
    } else {
      icon.classList.remove('fa-times');
      icon.classList.add('fa-bars');
    }
  }

  closeMenu() {
    this.navMenu.classList.remove('active');
    this.navToggle.classList.remove('active');
    
    const icon = this.navToggle.querySelector('i');
    icon.classList.remove('fa-times');
    icon.classList.add('fa-bars');
  }
}

// ===== SMOOTH SCROLLING NAVIGATION =====
class SmoothScrolling {
  constructor() {
    this.navLinks = document.querySelectorAll('.nav__link[href^="#"]');
    this.init();
  }

  init() {
    this.navLinks.forEach(link => {
      link.addEventListener('click', (e) => this.handleClick(e));
    });
  }

  handleClick(e) {
    e.preventDefault();
    
    const targetId = e.target.getAttribute('href');
    const targetSection = document.querySelector(targetId);
    
    if (targetSection) {
      const headerHeight = document.querySelector('.header').offsetHeight;
      const targetPosition = targetSection.offsetTop - headerHeight;
      
      window.scrollTo({
        top: targetPosition,
        behavior: 'smooth'
      });
    }
  }
}

// ===== HEADER SCROLL EFFECT =====
class HeaderScrollEffect {
  constructor() {
    this.header = document.querySelector('.header');
    this.lastScrollY = window.scrollY;
    this.init();
  }

  init() {
    this.ticking = false;
    window.addEventListener('scroll', () => this.requestTick(), { passive: true });
  }

  requestTick() {
    if (this.ticking) return;
    this.ticking = true;
    window.requestAnimationFrame(() => {
      this.handleScroll();
      this.ticking = false;
    });
  }

  handleScroll() {
    const currentScrollY = window.scrollY;
    
    if (currentScrollY > 100) {
      this.header.style.backgroundColor = 'rgba(255, 255, 255, 0.95)';
      this.header.style.backdropFilter = 'blur(10px)';
    } else {
      this.header.style.backgroundColor = '#ffffff';
      this.header.style.backdropFilter = 'none';
    }
    
    this.lastScrollY = currentScrollY;
  }
}

// ===== BUTTON INTERACTIONS =====
class ButtonInteractions {
  constructor() {
    this.buttons = document.querySelectorAll('.btn');
    this.init();
  }

  init() {
    this.buttons.forEach(button => {
      button.addEventListener('click', (e) => this.handleClick(e));
      button.addEventListener('mouseenter', (e) => this.handleHover(e));
      button.addEventListener('mouseleave', (e) => this.handleLeave(e));
    });
  }

  handleClick(e) {
    // Add ripple effect
    const button = e.currentTarget;
    const ripple = document.createElement('span');
    const rect = button.getBoundingClientRect();
    const size = Math.max(rect.width, rect.height);
    const x = e.clientX - rect.left - size / 2;
    const y = e.clientY - rect.top - size / 2;
    
    ripple.style.width = ripple.style.height = size + 'px';
    ripple.style.left = x + 'px';
    ripple.style.top = y + 'px';
    ripple.classList.add('ripple');
    
    button.appendChild(ripple);
    
    setTimeout(() => {
      ripple.remove();
    }, 600);
  }

  handleHover(e) {
    const button = e.currentTarget;
    button.style.transform = 'translateY(-2px)';
  }

  handleLeave(e) {
    const button = e.currentTarget;
    button.style.transform = 'translateY(0)';
  }
}

// ===== PARALLAX EFFECT =====
class ParallaxEffect {
  constructor() {
    this.heroBackground = document.querySelector('.hero__background');
    this.ctaBackground = document.querySelector('.cta__background');
    this.init();
  }

  init() {
    if (this.heroBackground || this.ctaBackground) {
      this.ticking = false;
      window.addEventListener('scroll', () => this.requestTick(), { passive: true });
    }
  }

  requestTick() {
    if (this.ticking) return;
    this.ticking = true;
    window.requestAnimationFrame(() => {
      this.handleScroll();
      this.ticking = false;
    });
  }

  handleScroll() {
    const scrolled = window.pageYOffset;
    const rate = scrolled * -0.5;
    
    if (this.heroBackground) {
      this.heroBackground.style.transform = `translateY(${rate}px)`;
    }
    
    if (this.ctaBackground) {
      this.ctaBackground.style.transform = `translateY(${rate * 0.3}px)`;
    }
  }
}

// ===== REVIEW SYSTEM =====
class ReviewSystem {
  constructor() {
    this.reviews = [];
    this.init();
  }

  init() {
    this.setupForm();
    window.addEventListener('load', () => this.loadReviews(), { once: true });
  }

  async loadReviews() {
    try {
      const response = await fetch('/get-reviews');
      const rows = await response.json();
      this.reviews = (rows || []).map(r => ({
        name: r.name,
        university: r.university,
        rating: Number(r.rating) || 0,
        review: r.review_text || r.review || '',
        date: r.created_at || ''
      }));
      this.displayReviews(this.reviews);
    } catch (error) {
      console.error('Failed to load reviews:', error);
      this.reviews = [];
      this.displayReviews(this.reviews);
    }
  }

  setupForm() {
    const form = document.getElementById('reviewForm');
    if (form) {
      form.addEventListener('submit', (e) => this.handleSubmit(e));
    }
  }

  async handleSubmit(e) {
    e.preventDefault();
    
    const formData = new FormData(e.target);
    const review = {
      name: formData.get('name'),
      university: formData.get('university'),
      rating: parseInt(formData.get('rating')),
      reviewText: formData.get('review')
    };

    // Validate form
    if (!review.name || !review.university || !review.rating || !review.reviewText) {
      this.showMessage('Please fill in all fields', 'error');
      return;
    }

    try {
      const response = await fetch('/submit-review', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          name: review.name,
          university: review.university,
          rating: review.rating,
          review_text: review.reviewText
        })
      });
      
      const result = await response.json();
      
      if (result.success) {
        this.showMessage('Thank you for your review!', 'success');
        e.target.reset();
        // Optimistically add the new review locally for immediate display
        this.reviews.unshift({
          name: review.name,
          university: review.university,
          rating: review.rating,
          review: review.reviewText,
          date: new Date().toISOString()
        });
        this.displayReviews(this.reviews);
      } else {
        this.showMessage('Failed to submit review. Please try again.', 'error');
      }
    } catch (error) {
      console.error('Review submission error:', error);
      this.showMessage('Failed to submit review. Please try again.', 'error');
    }
  }

  displayReviews(list) {
    const reviewsGrid = document.getElementById('reviewsGrid');
    if (!reviewsGrid) return;

    if (!list || list.length === 0) {
      reviewsGrid.innerHTML = '<p class="no-reviews">No reviews yet. Be the first to share your experience!</p>';
      return;
    }

    reviewsGrid.innerHTML = list.map(review => this.createReviewCard(review)).join('');
  }

  createReviewCard(review) {
    const stars = '★'.repeat(review.rating) + '☆'.repeat(5 - review.rating);
    const initials = review.name.split(' ').map(n => n[0]).join('').toUpperCase();
    
    return `
      <div class="review__card">
        <div class="review__stars">
          ${stars.split('').map(star => `<i class="fas fa-star" style="color: ${star === '★' ? '#ffc107' : '#e0e0e0'}"></i>`).join('')}
        </div>
        <p class="review__text">"${review.review}"</p>
        <div class="review__author">
          <div class="review__avatar">${initials}</div>
          <div>
            <div class="review__name">${review.name}</div>
            <div class="review__university">${review.university}</div>
          </div>
          <div class="review__date">${review.date}</div>
        </div>
      </div>
    `;
  }

  saveReviews() {
    localStorage.setItem('essaypro_reviews', JSON.stringify(this.reviews));
  }

  showMessage(message, type) {
    // Create message element
    const messageEl = document.createElement('div');
    messageEl.className = `message message--${type}`;
    messageEl.textContent = message;
    messageEl.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      padding: 12px 24px;
      border-radius: 8px;
      color: white;
      font-weight: 600;
      z-index: 1000;
      background: ${type === 'success' ? '#27ae60' : '#e74c3c'};
      box-shadow: 0 4px 12px rgba(0,0,0,0.15);
      transform: translateX(100%);
      transition: transform 0.3s ease;
    `;

    document.body.appendChild(messageEl);

    // Animate in
    setTimeout(() => {
      messageEl.style.transform = 'translateX(0)';
    }, 100);

    // Remove after 3 seconds
    setTimeout(() => {
      messageEl.style.transform = 'translateX(100%)';
      setTimeout(() => {
        document.body.removeChild(messageEl);
      }, 300);
    }, 3000);
  }
}

// ===== FORM VALIDATION =====
class FormValidation {
  constructor() {
    this.forms = document.querySelectorAll('form');
    this.init();
  }

  init() {
    this.forms.forEach(form => {
      form.addEventListener('submit', (e) => this.handleSubmit(e));
    });
  }

  handleSubmit(e) {
    // Form validation is now handled by ReviewSystem
    // This class can be used for other forms if needed
  }
}

// ===== PERFORMANCE OPTIMIZATION =====
class PerformanceOptimizer {
  constructor() {
    this.init();
  }

  init() {
    this.lazyLoadImages();
    this.debounceScrollEvents();
  }

  lazyLoadImages() {
    const images = document.querySelectorAll('img[data-src]');
    
    const imageObserver = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          const img = entry.target;
          img.src = img.dataset.src;
          img.classList.remove('lazy');
          imageObserver.unobserve(img);
        }
      });
    });

    images.forEach(img => imageObserver.observe(img));
  }

  debounceScrollEvents() {
    let scrollTimeout;
    
    const debouncedScroll = () => {
      clearTimeout(scrollTimeout);
      scrollTimeout = setTimeout(() => {
        // Handle scroll events here
      }, 10);
    };
    
    window.addEventListener('scroll', debouncedScroll, { passive: true });
  }
}

// ===== UTILITY FUNCTIONS =====
class Utils {
  static throttle(func, limit) {
    let inThrottle;
    return function() {
      const args = arguments;
      const context = this;
      if (!inThrottle) {
        func.apply(context, args);
        inThrottle = true;
        setTimeout(() => inThrottle = false, limit);
      }
    };
  }

  static debounce(func, wait, immediate) {
    let timeout;
    return function() {
      const context = this;
      const args = arguments;
      const later = function() {
        timeout = null;
        if (!immediate) func.apply(context, args);
      };
      const callNow = immediate && !timeout;
      clearTimeout(timeout);
      timeout = setTimeout(later, wait);
      if (callNow) func.apply(context, args);
    };
  }

  static isElementInViewport(el) {
    const rect = el.getBoundingClientRect();
    return (
      rect.top >= 0 &&
      rect.left >= 0 &&
      rect.bottom <= (window.innerHeight || document.documentElement.clientHeight) &&
      rect.right <= (window.innerWidth || document.documentElement.clientWidth)
    );
  }
}

// ===== CSS FOR RIPPLE EFFECT =====
const rippleCSS = `
  .btn {
    position: relative;
    overflow: hidden;
  }
  
  .ripple {
    position: absolute;
    border-radius: 50%;
    background-color: rgba(255, 255, 255, 0.3);
    transform: scale(0);
    animation: ripple-animation 0.6s linear;
    pointer-events: none;
  }
  
  @keyframes ripple-animation {
    to {
      transform: scale(4);
      opacity: 0;
    }
  }
`;

// Inject ripple CSS
const style = document.createElement('style');
style.textContent = rippleCSS;
document.head.appendChild(style);

// ===== INITIALIZE ALL COMPONENTS =====
document.addEventListener('DOMContentLoaded', () => {
  // Initialize all components
  new ScrollAnimations();
  new MobileNavigation();
  new SmoothScrolling();
  new HeaderScrollEffect();
  new ButtonInteractions();
  new ParallaxEffect();
  new ReviewSystem();
  new FormValidation();
  new PerformanceOptimizer();
  
  // Lightweight internal analytics (skip admin/auth pages and obvious bots)
  const path = window.location.pathname || '/';
  const ua = (navigator.userAgent || '').toLowerCase();
  const botHints = ['bot', 'crawl', 'spider', 'slurp', 'headless', 'facebookexternalhit', 'whatsapp', 'discordbot', 'telegrambot'];
  const isBot = Boolean(navigator.webdriver) || botHints.some(hint => ua.includes(hint));
  const isAdminPath = path.startsWith('/admin') || path.startsWith('/login') || path.startsWith('/admin-setup');

  if (!isBot && !isAdminPath) {
    const payload = JSON.stringify({ path });
    window.addEventListener('load', () => {
      if (navigator.sendBeacon) {
        const blob = new Blob([payload], { type: 'application/json' });
        const ok = navigator.sendBeacon('/track', blob);
        if (ok) return;
      }
      fetch('/track', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: payload,
        keepalive: true,
        credentials: 'same-origin'
      }).catch(() => {});
    }, { once: true });
  }

  // Add loading complete class
  document.body.classList.add('loaded');
  
  // Strip tracking query params from URL (e.g., utm_source=chatgpt.com)
  try {
    const url = new URL(window.location.href);
    const params = url.searchParams;
    const removeList = [];
    params.forEach((_, key) => {
      const k = key.toLowerCase();
      if (k.startsWith('utm_') || ['ref', 'referrer', 'gclid', 'fbclid', 'mc_cid', 'mc_eid'].includes(k)) {
        removeList.push(key);
      }
    });
    if (removeList.length > 0) {
      removeList.forEach((k) => params.delete(k));
      const newQuery = params.toString();
      const newUrl = url.origin + url.pathname + (newQuery ? `?${newQuery}` : '') + url.hash;
      window.history.replaceState({}, '', newUrl);
    }
  } catch (e) {
    // no-op
  }
  
  console.log('EssayPro website initialized successfully!');
});

// ===== ERROR HANDLING =====
window.addEventListener('error', (e) => {
  console.error('JavaScript error:', e.error);
});

// ===== EXPORT FOR MODULE USAGE (if needed) =====
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    ScrollAnimations,
    MobileNavigation,
    SmoothScrolling,
    HeaderScrollEffect,
    ButtonInteractions,
    ParallaxEffect,
    FormValidation,
    PerformanceOptimizer,
    Utils
  };
}
